import sys  # Moduli per la gestione del path di sistema
import pathlib

# Aggiunge la cartella radice 'backend' a sys.path per permettere gli import assoluti 'from app....'
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings  # Modulo di configurazione e variabili d'ambiente
from app.api.schemas import AnalysisRequest, AnalysisResponse
from app.analyzers.dom_analyzer import DOMAnalyzer

# Creazione dell'app FastAPI con configurazioni di base e middleware CORS, http://localhost:8000/docs per la documentazione Swagger UI
app = FastAPI( 
    title=settings.APP_NAME,
    version="2.1.1",
    description="Engine di rilevamento e mitigazione in tempo reale di attacchi Browser-in-the-Middle (BitM) tramite LLM."
)

# Configurazione CORS restrittiva: autorizza esclusivamente estensioni Chrome e localhost, disabilitando credentials
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^chrome-extension://.*",
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
# Configurazione endpoint FastAPI
@app.get("/")  # Endpoint principale di verifica stato su http://localhost:8000/
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
async def health_check():  # Controllo dello stato di salute del backend e del modello LLM attivo
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "provider": settings.LLM_PROVIDER,
        "model": settings.LLM_MODEL
    }

# Endpoint principale di analisi: riceve il payload JSON strutturato dal browser
@app.post(f"{settings.API_PREFIX}/analyze", response_model=AnalysisResponse)
async def analyze_page(request: AnalysisRequest):
    """
    Endpoint invocato dall'estensione browser per analizzare i dati DOM ed estrarre la valutazione di rischio BitM.
    """
    response = await DOMAnalyzer.process_analysis(request)
    return response

# Uvicorn server: bind esclusivo su loopback 127.0.0.1 per impedire accessi non autorizzati da LAN/Wi-Fi
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
