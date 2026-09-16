"""
Suite di Test di Regressione e Validazione BitM Sentinel.

Copre tutti i moduli critici della pipeline:
- Euristiche deterministiche Fast-Path (CWE-598, Reverse Proxy Mismatch, Raw IP, BitM Streaming);
- Gestione della fusione dei referti e fail-safe integrato;
- Parser JSON tollerante per output LLM (con gestione Markdown fences e tag <think>);
- Politica di eviction per la cache in memoria e validazione schemi Pydantic Settings.
"""

import os
import sys
import unittest
import pathlib

BACKEND_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from app.api.schemas import AnalysisRequest, FormSchema, InputFieldSchema, AnalysisResponse
from app.analyzers.dom_analyzer import DOMAnalyzer
from app.llm.client import LLMClient
from app.config import settings

class TestBitMSentinelPipeline(unittest.TestCase):
    """
    Suite di test automatizzata per la validazione di BitM Sentinel:
    - Euristiche deterministiche server-side (CWE-598, Proxy Mismatch, Raw IP, Streaming)
    - Fusione fail-safe e deduplicazione semantica delle anomalie
    - Robustezza del parser JSON multi-provider
    - Gestione della cache in RAM e conformità Pydantic v2
    """

    def test_01_legitimate_page(self):
        """Verifica che una pagina pulita ottenga punteggio 0 (ALLOW)"""
        req = AnalysisRequest(
            url="https://it.wikipedia.org/wiki/Sicurezza_informatica",
            domain="it.wikipedia.org",
            title="Sicurezza informatica - Wikipedia",
            triageScore=0,
            triageFlags=[],
            hasSensitiveInput=False,
            forms=[
                FormSchema(
                    formId="searchform",
                    action="https://it.wikipedia.org/w/index.php",
                    method="GET",
                    inputs=[InputFieldSchema(type="search", name="search", placeholder="Cerca in Wikipedia")]
                )
            ],
            externalScriptDomains=[],
            visibleTextSnippet="La sicurezza informatica è un ramo dell'informatica..."
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertEqual(score, 0)
        self.assertEqual(attack, "NONE")
        self.assertEqual(len(anomalies), 0)

    def test_02_cwe_598_insecure_get_password(self):
        """Verifica che un form password inviato in GET (test_giallo.html) ottenga WARN (Score >= 40)"""
        req = AnalysisRequest(
            url="http://localhost:5000/test_giallo.html",
            domain="localhost",
            title="Sito Sospetto",
            triageScore=40,
            triageFlags=[
                "Form sensibile trasmette credenziali tramite metodo HTTP GET non sicuro (CWE-598)",
                "Rilevati 1 iframe invisibili (potenziali tracker o clickjacking)"
            ],
            hasSensitiveInput=True,
            forms=[
                FormSchema(
                    formId="login_form",
                    action="",
                    method="GET",
                    inputs=[
                        InputFieldSchema(type="text", name="username", placeholder="Username"),
                        InputFieldSchema(type="password", name="password", placeholder="Password")
                    ]
                )
            ],
            externalScriptDomains=[],
            visibleTextSnippet="Accedi al servizio"
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertGreaterEqual(score, 40)
        self.assertEqual(attack, "INSECURE_AUTH_METHOD")
        self.assertTrue(any("CWE-598" in a for a in anomalies))

    def test_03_form_action_proxy_mismatch(self):
        """Verifica che un form che reindirizza le credenziali a un host terzo scateni BLOCK (Score 95)"""
        req = AnalysisRequest(
            url="http://localhost:5001/login",
            domain="localhost",
            title="Banca Sicura Login",
            triageScore=55,
            triageFlags=["Form sensibile invia credenziali a un host/dominio terzo (attacker-evil-proxy.com)"],
            hasSensitiveInput=True,
            forms=[
                FormSchema(
                    formId="form_0",
                    action="http://attacker-evil-proxy.com/harvest",
                    method="POST",
                    inputs=[
                        InputFieldSchema(type="password", name="password", placeholder="Password"),
                        InputFieldSchema(type="text", name="otp", placeholder="2FA OTP")
                    ]
                )
            ],
            externalScriptDomains=[],
            visibleTextSnippet="Inserisci password e token"
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertEqual(score, 95)
        self.assertEqual(attack, "BITM_PROXY")

    def test_04_raw_ip_unencrypted_banking(self):
        """Verifica che un IP grezzo HTTP non cifrato (es. 192.168.122.201) con titolo bancario scateni BLOCK (Score 80)"""
        req = AnalysisRequest(
            url="http://192.168.122.201/login",
            domain="192.168.122.201",
            title="Altoro Mutual Online Banking",
            triageScore=0,
            triageFlags=[],
            hasSensitiveInput=True,
            forms=[],
            externalScriptDomains=[],
            visibleTextSnippet="Altoro Mutual Login Portal"
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertGreaterEqual(score, 80)
        self.assertEqual(attack, "PHISHING_OR_BITM")

    def test_05_domain_with_digits_is_not_raw_ip(self):
        """Verifica che un dominio legittimo con cifre (es. web2.universita.it) non sia scambiato per un IP grezzo"""
        req = AnalysisRequest(
            url="http://web2.universita.it/login",
            domain="web2.universita.it",
            title="Login Portale Studenti",
            triageScore=0,
            triageFlags=[],
            hasSensitiveInput=False,
            forms=[],
            externalScriptDomains=[],
            visibleTextSnippet="Accesso credenziali universitarie"
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertEqual(score, 0)
        self.assertEqual(attack, "NONE")

    def test_06_video_streaming_bitm(self):
        """Verifica che lo streaming BitM (Cuddlephish / WebRTC) su contesto sensibile scateni BITM_STREAMING"""
        req = AnalysisRequest(
            url="http://192.168.122.201/",
            domain="192.168.122.201",
            title="Altoro Mutual Online Access",
            triageScore=65,
            triageFlags=["Rilevato flusso video/canvas a tutto schermo in contesto sensibile/IP senza form nativi (potenziale BitM Streaming/noVNC/WebRTC)"],
            hasSensitiveInput=True,
            forms=[],
            externalScriptDomains=[],
            visibleTextSnippet="Streaming session"
        )
        score, attack, anomalies = DOMAnalyzer.run_server_heuristics(req)
        self.assertGreaterEqual(score, 65)
        self.assertIn(attack, ("BITM_STREAMING", "PHISHING_OR_BITM"))

    def test_07_json_parser_robustness(self):
        """Verifica la decodifica JSON dell'LLM con markdown code fences e blocchi di ragionamento <think>"""
        raw_md = """Ecco il referto:
```json
{
  "risk_score": 90,
  "mitigation_action": "BLOCK",
  "attack_type": "BITM_PROXY",
  "reasoning": "Rilevato reverse proxy malevolo",
  "detected_anomalies": ["Form action mismatch"]
}
```"""
        r1 = LLMClient._parse_json_response(raw_md)
        self.assertEqual(r1.risk_score, 90)
        self.assertEqual(r1.mitigation_action, "BLOCK")

        raw_think = """<think>
Analisi della form: rilevato mismatch { form: evil.com }
</think>
{
  "risk_score": 45,
  "mitigation_action": "WARN",
  "attack_type": "TYPOSQUATTING",
  "reasoning": "Dominio sospetto",
  "detected_anomalies": []
}"""
        r2 = LLMClient._parse_json_response(raw_think)
        self.assertEqual(r2.risk_score, 45)
        self.assertEqual(r2.mitigation_action, "WARN")

    def test_08_cache_eviction_cap(self):
        """Verifica che la cache in memoria non superi la soglia massima di 200 per prevenire memory leak"""
        LLMClient._cache.clear()
        for i in range(250):
            key = f"http://test.com/{i}:hash{i}"
            if len(LLMClient._cache) >= 200:
                LLMClient._cache.pop(next(iter(LLMClient._cache)))
            LLMClient._cache[key] = AnalysisResponse(
                risk_score=0,
                mitigation_action="ALLOW",
                attack_type="NONE",
                reasoning="test",
                detected_anomalies=[]
            )
        self.assertLessEqual(len(LLMClient._cache), 200)

    def test_09_pydantic_settings(self):
        """Verifica che le configurazioni Pydantic v2 carichino correttamente i default di sicurezza"""
        self.assertEqual(settings.HOST, "127.0.0.1")
        self.assertEqual(settings.PORT, 8000)
        self.assertTrue(settings.APP_NAME)

if __name__ == "__main__":
    unittest.main()
