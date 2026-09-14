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
        # Smistamento dei modelli LLM in base al provider configurato nel file .env
        provider = settings.LLM_PROVIDER.strip().lower()
        model_name = settings.LLM_MODEL.strip()
        user_prompt = build_user_prompt(payload) #funzione file prompts.py

        try:
            if provider == "ollama":
                response = await LLMClient._call_ollama(model_name, user_prompt)
            elif provider == "gemini":
                response = await LLMClient._call_gemini(model_name, user_prompt)
            elif provider in ("openai", "deepseek"):
                response = await LLMClient._call_openai(model_name, user_prompt)
            else:
                response = await LLMClient._call_openai(model_name, user_prompt)

            # Salva in cache solo se la risposta è valida (con eviction per prevenire memory leak)
            if len(LLMClient._cache) >= 200:
                LLMClient._cache.pop(next(iter(LLMClient._cache)))
            LLMClient._cache[cache_key] = response
            return response

        # Fallback in caso di errori o indisponibilità dell'LLM: ritorno gestito dall'engine euristico
        except Exception as e:
            import traceback
            print(f"[LLMClient Error] Fallimento chiamata LLM ({provider}/{model_name}): {repr(e)}")
            traceback.print_exc()
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

        from google import genai
        from google.genai import types
        from google.genai.errors import APIError

        client = genai.Client(api_key=settings.GEMINI_API_KEY)

        last_error = None
        for attempt in range(retries):
            try:
                print(f"\n[Gemini API - {model}] Invio richiesta in corso (Tentativo {attempt+1}/{retries})...")

                response = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=BITM_SYSTEM_PROMPT,
                            temperature=0.1,
                            response_mime_type="application/json",
                            response_schema=AnalysisResponse,
                        )
                    ),
                    timeout=30.0
                )
                
                print(f"[Gemini API - {model}] Risposta ricevuta correttamente!")
                if response.text:
                    print(f"[Gemini Debug JSON] {response.text}")

                if hasattr(response, "parsed") and response.parsed:
                    return response.parsed
                elif response.text:
                    return LLMClient._parse_json_response(response.text)
                else:
                    finish_reason = "UNKNOWN"
                    if hasattr(response, "candidates") and response.candidates:
                        finish_reason = getattr(response.candidates[0], "finish_reason", "BLOCKED")
                    last_error = f"Risposta vuota o bloccata dai filtri di sicurezza Google (finish_reason: {finish_reason})"
                    print(f"[Gemini Warning on {model}]: {last_error}")
                    continue

            except (asyncio.TimeoutError, TimeoutError):
                last_error = "Timeout (30s) superato durante l'attesa dei server Google Gemini"
                print(f"[Gemini Timeout on {model}]: {last_error}")
                break
            except APIError as e:
                print(f"[Gemini APIError on {model}]: Code {e.code} - {e.message}")
                if e.code == 429: # Rate Limit
                    print(f"[Gemini 429 Rate Limit] Tentativo {attempt+1}/{retries}. Attesa di 2 sec...")
                    await asyncio.sleep(2)
                    continue
                last_error = f"APIError {e.code}: {e.message}"
                break
            except Exception as e:
                print(f"[Gemini Exception on {model}]: {repr(e)}")
                last_error = str(e) if str(e) else repr(e)
                break

        raise Exception(f"Gemini API Error: {last_error or 'Nessuna risposta valida ricevuta dalle API'}")

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

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            if content:
                print(f"[Ollama Debug JSON] {content}")
            return LLMClient._parse_json_response(content)

    @staticmethod
    async def _call_openai(model: str, user_prompt: str) -> AnalysisResponse:
        """Invia la richiesta a OpenAI o provider compatibili (es. DeepSeek)"""
        if not settings.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY non configurata nel file .env")

        from openai import AsyncOpenAI
        
        # Rilevamento automatico DeepSeek
        is_deepseek = "deepseek" in model.lower()
        base_url = "https://api.deepseek.com" if is_deepseek else None
        
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=base_url)
        
        if is_deepseek:
            # DeepSeek supporta la modalità JSON standard
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": BITM_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            content = response.choices[0].message.content
            return LLMClient._parse_json_response(content)
        else:
            # OpenAI nativo supporta i Pydantic Structured Outputs (Beta)
            response = await client.beta.chat.completions.parse(
                model=model,
                messages=[
                    {"role": "system", "content": BITM_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                response_format=AnalysisResponse,
                temperature=0.1
            )
            if response.choices[0].message.parsed:
                return response.choices[0].message.parsed
            else:
                return LLMClient._parse_json_response(response.choices[0].message.content)

    #esegue il parsing della risposta JSON grezza dell'LLM e la converte in un oggetto AnalysisResponse
    @staticmethod
    def _parse_json_response(raw_text: str) -> AnalysisResponse:
        import re
        import json
        
        # 1. Rimuove blocchi <think>...</think> (es. DeepSeek R1)
        cleaned = re.sub(r'<think>[\s\S]*?</think>', '', raw_text).strip()

        parsed = None
        # 2. Prova a decodificare direttamente se il testo è già un JSON puro
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            # 3. Estrae blocchi markdown ```json ... ```
            md_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', cleaned)
            if md_match:
                try:
                    parsed = json.loads(md_match.group(1))
                except json.JSONDecodeError:
                    parsed = None

            # 4. Fallback: delimitazione esatta dalla prima '{' all'ultima '}'
            if not parsed:
                start_idx = cleaned.find('{')
                end_idx = cleaned.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        parsed = json.loads(cleaned[start_idx:end_idx + 1])
                    except json.JSONDecodeError:
                        raise ValueError("Nessun JSON valido trovato nella risposta dell'LLM.")
                else:
                    raise ValueError("Nessun JSON valido trovato nella risposta dell'LLM.")
        
        return AnalysisResponse(
            risk_score=int(parsed.get("risk_score", 0)),
            mitigation_action=str(parsed.get("mitigation_action", "ALLOW")).upper(),
            attack_type=str(parsed.get("attack_type", "NONE")),
            reasoning=str(parsed.get("reasoning", "Nessuna anomalia rilevata.")),
            detected_anomalies=parsed.get("detected_anomalies", [])
        )
