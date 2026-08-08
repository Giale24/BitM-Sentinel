import json
import asyncio
import httpx
import hashlib
from app.config import settings
from app.api.schemas import AnalysisResponse
from app.llm.prompts import BITM_SYSTEM_PROMPT, build_user_prompt

class LLMClient:
    """
    Client unificato per la gestione di modelli LLM con caching in memoria e retry automatico.
    """
    _cache = {}  # Cache in memoria per evitare chiamate ripetute sullo stesso URL/payload

    #esegue l'hash per poi usarla come entry per la cache in memoria, evitando chiamate ripetute allo stesso URL/payload
    @staticmethod
    async def analyze_page(payload: dict) -> AnalysisResponse:
        url = payload.get("url", "")
        payload_hash = hashlib.md5(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        cache_key = f"{url}:{payload_hash}"

        # Ritorna il risultato dalla cache se disponibile
        if cache_key in LLMClient._cache:
            print(f"[LLMClient Cache Hit] Risposta recuperata dalla cache locale per: {url}")
            return LLMClient._cache[cache_key]
        # Smistamento dei modelli LLM in base al provider configurato nel file .env, con fallback su Gemini se non specificato
        provider = settings.LLM_PROVIDER.lower()
        model_name = settings.LLM_MODEL
        user_prompt = build_user_prompt(payload) #funzione file prompts.py

        try:
            if provider == "ollama":
                response = await LLMClient._call_ollama(model_name, user_prompt)
            elif provider == "gemini":
                response = await LLMClient._call_gemini(model_name, user_prompt)
            elif provider == "openai":
                response = await LLMClient._call_openai(model_name, user_prompt)
            else:
                response = await LLMClient._call_gemini(model_name, user_prompt)

            # Salva in cache
            LLMClient._cache[cache_key] = response
            return response

        #fallback in caso di errori o superamento della quota LLM, ritorna un risultato euristico gestito dal backend
        except Exception as e:
            print(f"[LLMClient Error] Fallimento chiamata LLM ({provider}/{model_name}): {e}")
            return AnalysisResponse(
                risk_score=0,
                mitigation_action="ALLOW",
                attack_type="NONE",
                reasoning=f"Quota LLM ({provider}) temporaneamente superata o API non disponibile. Risultato gestito dall'Engine Euristico Backend.",
                detected_anomalies=payload.get("triageFlags", [])
            )

    @staticmethod
    async def _call_gemini(model: str, user_prompt: str, retries: int = 2) -> AnalysisResponse:
        """Invia la richiesta a Google Gemini API usando l'SDK ufficiale (google-genai)"""
        if not settings.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY non configurata nel file .env")

        from google import genai #importate se utilizziamo Google Gemini come provider LLM
        from google.genai import types
        from google.genai.errors import APIError

        client = genai.Client(api_key=settings.GEMINI_API_KEY)

        # Se il modello primario è in rate limit, proviamo con gemini-3.6-flash
        models_to_try = [model]
        if "gemini-3.6-flash" not in model: #fallback su gemini-3.6-flash se il modello primario è in rate limit e se non è già quello configurato nel file .env
            models_to_try.append("gemini-3.6-flash")

        last_error = None
        for current_model in models_to_try:
            for attempt in range(retries):
                try:
                    print(f"\n[Gemini API - {current_model}] Invio richiesta in corso (Tentativo {attempt+1}/{retries})...")
                    # Se vuoi vedere l'intero prompt decommenta la riga sotto:
                    # print(f"[Gemini API] Prompt:\n{user_prompt}\n")

                    response = await client.aio.models.generate_content(
                        model=current_model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=BITM_SYSTEM_PROMPT,
                            temperature=0.1,
                            response_mime_type="application/json",
                            response_schema=AnalysisResponse,
                        )
                    )
                    
                    print(f"[Gemini API - {current_model}] Risposta ricevuta correttamente!")
                    # Stampa il testo grezzo restituito dall'LLM per debug
                    if response.text:
                        print(f"[Gemini Debug JSON] {response.text}")

                    if hasattr(response, "parsed") and response.parsed:
                        return response.parsed
                    elif response.text:
                        return LLMClient._parse_json_response(response.text)

                    #gestione errore 429
                except APIError as e:
                    if e.code == 429: # Rate Limit
                        print(f"[Gemini 429 Rate Limit] Tentativo {attempt+1}/{retries} su {current_model}. Attesa di 2 sec...")
                        await asyncio.sleep(2) # await per 2 secondi prima di riprovare
                        continue
                    last_error = str(e)
                    break # Interrompi i tentativi su errori non 429
                except Exception as e:
                    last_error = str(e)
                    break # Interrompi sui fallimenti SDK generici

        raise Exception(f"Gemini API Error: {last_error or '429 Too Many Requests (Quota superata)'}")

    @staticmethod
    async def _call_ollama(model: str, user_prompt: str) -> AnalysisResponse:
        url = f"{settings.OLLAMA_BASE_URL}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": BITM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            "format": "json",
            "stream": False
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            return LLMClient._parse_json_response(content)

    @staticmethod
    async def _call_openai(model: str, user_prompt: str) -> AnalysisResponse:
        """Invia la richiesta a OpenAI usando le funzionalità beta Structured Outputs (Pydantic)"""
        if not settings.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY non configurata nel file .env")

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        
        response = await client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": BITM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            response_format=AnalysisResponse,
            temperature=0.1 #freddezza del modello
        )
        return response.choices[0].message.parsed

    #esegue il parsing della risposta JSON grezza dell'LLM e la converte in un oggetto AnalysisResponse
    @staticmethod
    def _parse_json_response(raw_text: str) -> AnalysisResponse:
        clean_text = raw_text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]

        parsed = json.loads(clean_text)
        return AnalysisResponse(
            risk_score=int(parsed.get("risk_score", 0)),
            mitigation_action=str(parsed.get("mitigation_action", "ALLOW")).upper(),
            attack_type=str(parsed.get("attack_type", "NONE")),
            reasoning=str(parsed.get("reasoning", "Nessuna anomalia rilevata.")),
            detected_anomalies=parsed.get("detected_anomalies", [])
        )
