from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# Definizione degli schemi Pydantic v2 per la validazione rigorosa dei contratti API

class InputFieldSchema(BaseModel):
    """Rappresenta un singolo campo di input HTML all'interno di un form."""
    type: str
    name: str
    placeholder: Optional[str] = ""

class FormSchema(BaseModel):
    """Rappresenta un form HTML scansionato con i suoi campi e la destinazione action."""
    formId: str
    action: str
    method: str
    inputs: List[InputFieldSchema]

class AnalysisRequest(BaseModel):
    """
    Payload trasmesso dal Service Worker dell'estensione a FastAPI.
    Raggruppa le caratteristiche strutturali e semantiche del DOM per l'analisi.
    """
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
    """
    Contratto dati vincolante restituito al client e imposto come Structured Output all'LLM.
    """
    risk_score: int = Field(..., description="Punteggio di rischio normalizzato da 0 a 100")
    mitigation_action: str = Field(..., description="Azione esecutiva per il client: ALLOW, WARN, o BLOCK")
    attack_type: str = Field(..., description="Classificazione della minaccia (es. NONE, BITM_PROXY, BITM_STREAMING, TYPOSQUATTING)")
    reasoning: str = Field(..., description="Motivazione semantica trasparente prodotta dall'LLM")
    detected_anomalies: List[str] = Field(default_factory=list, description="Lista consolidata delle anomalie riscontrate")
