import sys #moduli per la gestione del path di importazione
import pathlib

# Aggiunge la cartella 'backend' a sys.path per permettere gli import 'from app....'
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent)) #path injection per importare moduli da 'backend/app'

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings #nostri moduli di configurazione
from app.api.schemas import AnalysisRequest, AnalysisResponse
from app.analyzers.dom_analyzer import DOMAnalyzer

# Creazione dell'app FastAPI con configurazioni di base e middleware CORS, http://localhost:8000/docs per la documentazione Swagger UI
app = FastAPI( 
    title=settings.APP_NAME,
    version="1.0.0",
    description="Engine di rilevamento e mitigazione in tempo reale di attacchi Browser-in-the-Middle (BitM) tramite LLM."
)

# Abilita CORS per permettere chiamate dalle estensioni browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"], # accetta tutte le richieste HTTP (GET, POST, etc.)
    allow_headers=["*"],
)
#configurazione endpopoin FastAPI 
@app.get("/") #chiama l'endpoint principale per verificare lo stato dell'applicazione su localhost:8000/
async def root():
    return {
        "message": "BitM Sentinel LLM Backend Engine is running!",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "analyze": f"{settings.API_PREFIX}/analyze (POST only via Chrome Extension)"
        }
    }

@app.get("/health")
async def health_check():#check dello stato di salute dell'applicazione e del provider LLM configurato 
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "provider": settings.LLM_PROVIDER,
        "model": settings.LLM_MODEL
    }
#usiamo POST per il payload JSON
@app.post(f"{settings.API_PREFIX}/analyze", response_model=AnalysisResponse)
async def analyze_page(request: AnalysisRequest):
    """
    Endpoint invocato dall'estensione browser per analizzare i dati DOM ed estrarre la valutazione di rischio BitM.
    """
    response = await DOMAnalyzer.process_analysis(request)
    return response
#uvicorn server per eseguire l'applicazione FastAPI in locale, con ricarica automatica per lo sviluppo, inotre permette l'asinc/await per le chiamate asincrone all'LLM e alle euristiche server-side.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
