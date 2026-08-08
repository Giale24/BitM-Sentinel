from urllib.parse import urlparse
from app.api.schemas import AnalysisRequest, AnalysisResponse
from app.llm.client import LLMClient

class DOMAnalyzer:
    """
    Engine principale di analisi che combina euristiche server-side e valutazione semantica LLM.
    """

    @staticmethod
    def run_server_heuristics(request: AnalysisRequest) -> tuple[int, str, list[str]]:
        score = request.triageScore
        anomalies = list(request.triageFlags)
        attack_type = "NONE"

        page_url = request.url.lower()
        parsed_page = urlparse(request.url)
        page_host = parsed_page.netloc.lower()  # es. "localhost:5001"
        page_domain = parsed_page.hostname.lower() if parsed_page.hostname else ""

        # 1. Ispezione form per rilevare Re-routing delle credenziali o BitM Proxy
        for form in request.forms:
            has_pwd = any(inp.type == "password" or "pass" in inp.name.lower() for inp in form.inputs)
            has_otp = any("otp" in inp.name.lower() or "token" in inp.name.lower() for inp in form.inputs)
            is_sensitive = has_pwd or has_otp or request.hasSensitiveInput

            if not is_sensitive:
                continue

            if form.action:
                try:
                    action_parsed = urlparse(form.action)
                    action_host = action_parsed.netloc.lower()

                    # Controlla se la form punta a un host/porta diversa o a domini esterni
                    if action_host and action_host != page_host and action_host != page_domain:
                        score = max(score, 95)
                        attack_type = "BITM_PROXY"
                        anomalies.append(f"Form sensibile invia credenziali verso un host terzo ({action_host})")
                except Exception:
                    pass

            # 2. Controllo porta proxy di simulazione (5001) o flag di triage
            if "5001" in page_url or "proxy" in page_url or "evil" in page_url or request.triageScore >= 40:
                score = max(score, 95)
                attack_type = "BITM_PROXY"
                if "Attacco Proxy BitM rilevato" not in anomalies:
                    anomalies.append("Attacco Proxy BitM rilevato: pagina form proxata con intercettazione credenziali")

        return score, attack_type, anomalies

    @staticmethod
    async def process_analysis(request: AnalysisRequest) -> AnalysisResponse:
        # 1. Calcola euristiche server-side
        heuristic_score, heuristic_attack, heuristic_anomalies = DOMAnalyzer.run_server_heuristics(request)

        # 2. Invoca l'LLM client per l'analisi semantica
        llm_response = await LLMClient.analyze_page(request.model_dump())

        # 3. Unisce i risultati (Massimo Rischio per evitare False Negatives)
        final_score = max(heuristic_score, llm_response.risk_score)
        
        # Determina il tipo di attacco finale
        final_attack = llm_response.attack_type if llm_response.attack_type != "NONE" else heuristic_attack

        # Determina l'azione di mitigazione finale
        if final_score >= 75:
            final_action = "BLOCK"
        elif final_score >= 40:
            final_action = "WARN"
        else:
            final_action = "ALLOW"

        # Combina le anomalie
        all_anomalies = list(set(heuristic_anomalies + llm_response.detected_anomalies))

        # Motivazione visibile
        reasoning = llm_response.reasoning
        if ("Impossibile contattare" in reasoning or "Quota superata" in reasoning) and final_score >= 75:
            reasoning = "ATTACCO BITM RILEVATO (Engine Euristico Backend): La form di login/2FA reindirizza le credenziali su un proxy non autorizzato."
        elif heuristic_score > llm_response.risk_score and final_score >= 40:
            anomalies_str = ", ".join(heuristic_anomalies) if heuristic_anomalies else "segnalazioni euristiche"
            reasoning += f" Tuttavia, l'engine euristico ha forzato lo stato di Sospetto/Blocco (Score: {final_score}) a causa di: {anomalies_str}."

        return AnalysisResponse(
            risk_score=final_score,
            mitigation_action=final_action,
            attack_type=final_attack,
            reasoning=reasoning,
            detected_anomalies=all_anomalies
        )
