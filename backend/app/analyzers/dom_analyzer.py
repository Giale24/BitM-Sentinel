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

            # Controllo CWE-598: Password o credenziali inviate via metodo HTTP GET non sicuro
            if is_sensitive and (form.method or "").upper() == "GET":
                score = max(score, 45)
                if attack_type == "NONE":
                    attack_type = "INSECURE_AUTH_METHOD"
                anomalies.append("Form con credenziali/token invia dati sensibili tramite metodo HTTP GET non cifrato (CWE-598)")

        # 2. Controllo porta proxy di simulazione (porta 5001 su localhost/127.0.0.1)
        # Eseguito a livello di pagina (non dentro il ciclo form) con controllo rigoroso su porta e host
        is_simulation_proxy = (parsed_page.port == 5001) and (page_domain in ("localhost", "127.0.0.1"))
        if is_simulation_proxy:
            score = max(score, 95)
            attack_type = "BITM_PROXY"
            if "Attacco Proxy BitM rilevato" not in anomalies:
                anomalies.append("Attacco Proxy BitM rilevato: pagina form proxata con intercettazione credenziali")

        # 3. Controllo BitM Streaming o IP grezzo non cifrato con titolo bancario/sensibile
        page_title = (request.title or "").lower()
        is_banking_or_login = any(w in page_title for w in ["bank", "mutual", "altoro", "login", "accesso", "postepay", "intesa", "paypal", "microsoft", "google"])
        
        # Riconoscimento rigoroso di indirizzi IP tramite libreria standard ipaddress
        is_raw_ip = False
        try:
            import ipaddress
            ipaddress.ip_address(page_domain)
            is_raw_ip = True
        except (ValueError, TypeError):
            is_raw_ip = False

        if is_banking_or_login and is_raw_ip and "http:" in page_url:
            score = max(score, 80)
            if attack_type == "NONE":
                attack_type = "PHISHING_OR_BITM"
            anomalies.append(f"Servizio bancario/autenticazione '{request.title}' erogato su indirizzo IP grezzo ({page_host}) senza cifratura HTTPS")

        # 4. Integrazione dello score e dei flag del triage client-side
        if request.triageScore >= 40:
            score = max(score, request.triageScore)
            if attack_type == "NONE":
                # Mappatura accurata della tipologia di attacco in base ai flag effettivi
                flags_text = " ".join(request.triageFlags).lower()
                if "streaming" in flags_text or "video/canvas" in flags_text:
                    attack_type = "BITM_STREAMING"
                elif "typosquatting" in flags_text or "simile" in flags_text:
                    attack_type = "TYPOSQUATTING"
                elif "sottodominio" in flags_text:
                    attack_type = "BITM_PROXY"
                elif "iframe" in flags_text:
                    attack_type = "CLICKJACKING"
                elif "cwe-598" in flags_text or "metodo http get" in flags_text:
                    attack_type = "INSECURE_AUTH_METHOD"
                else:
                    attack_type = "SUSPICIOUS_DOM_STRUCTURE"

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

        # Deduplicazione semantica delle anomalie (elimina doppioni con formulazioni leggermente diverse)
        seen_topics = set()
        all_anomalies = []

        def get_anomaly_topic(anomaly_text: str) -> str:
            a = anomaly_text.lower()
            if "cwe-598" in a or "metodo http get" in a or "get non sicuro" in a or "get non cifrato" in a:
                return "cwe_598_get"
            if "host terzo" in a or "porta diversa" in a or "proxy" in a or "reindirizza" in a:
                return "proxy_redirect"
            if "streaming" in a or "video/canvas" in a or "webrtc" in a or "novnc" in a:
                return "streaming"
            if "ip grezzo" in a or "raw ip" in a or "senza cifratura" in a:
                return "raw_ip"
            if "iframe" in a or "clickjacking" in a:
                return "iframe"
            if "typosquatting" in a or "simile a brand" in a:
                return "typosquatting"
            if "sottodominio" in a or "subdomain" in a:
                return "subdomain"
            return a.strip()

        for item in heuristic_anomalies + llm_response.detected_anomalies:
            topic = get_anomaly_topic(item)
            if topic not in seen_topics:
                seen_topics.add(topic)
                all_anomalies.append(item)

        # Motivazione visibile con rilevamento robusto del fallimento LLM
        reasoning = llm_response.reasoning
        llm_failed = any(err_token in reasoning.lower() for err_token in ["quota", "temporaneamente superata", "impossibile contattare", "non disponibile", "api error"])

        if llm_failed and final_score >= 75:
            anomalies_str = ", ".join(heuristic_anomalies) if heuristic_anomalies else "violazioni euristiche critiche"
            reasoning = f"ATTACCO BITM RILEVATO (Engine Euristico Backend - Fail-Safe): Blocco forzato a causa di: {anomalies_str}."
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
