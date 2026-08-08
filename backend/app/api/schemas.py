from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# Definizione degli schemi Pydantic per le richieste e risposte dell'API
class InputFieldSchema(BaseModel):
    type: str
    name: str
    placeholder: Optional[str] = ""

class FormSchema(BaseModel):
    formId: str
    action: str
    method: str
    inputs: List[InputFieldSchema]

class AnalysisRequest(BaseModel):
    url: str
    domain: str
    title: str
    triageScore: int = 0
    triageFlags: List[str] = []
    hasSensitiveInput: bool = False
    forms: List[FormSchema] = []
    externalScriptDomains: List[str] = []
    visibleTextSnippet: Optional[str] = ""

class AnalysisResponse(BaseModel):
    risk_score: int = Field(..., description="Punteggio di rischio da 0 a 100")
    mitigation_action: str = Field(..., description="Azione raccomandata: ALLOW, WARN, o BLOCK")
    attack_type: str = Field(..., description="Tipo di minaccia rilevata: NONE, BITM_PROXY, TYPOSQUATTING, PHISHING_OVERLAY, CROSS_DOMAIN_FORM")
    reasoning: str = Field(..., description="Spiegazione sintetica della decisione dell'LLM")
    detected_anomalies: List[str] = Field(default_factory=list, description="Lista di anomalie trovate nel DOM/sessione")
