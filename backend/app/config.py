import pathlib
from pydantic_settings import BaseSettings, SettingsConfigDict

# Percorso assoluto al file .env nella root di backend/
ENV_PATH = pathlib.Path(__file__).resolve().parent.parent / ".env"

class Settings(BaseSettings):
    """
    Configurazione centralizzata dell'applicazione basata su Pydantic Settings.
    Carica automaticamente le variabili dal file .env e convalida i tipi di dato.
    """
    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "BitM Sentinel Engine"
    API_PREFIX: str = "/api/v1"
    
    # Provider predefinito e modello LLM ('gemini', 'deepseek', 'ollama', 'openai')
    LLM_PROVIDER: str = "gemini"
    LLM_MODEL: str = "gemini-3.5-flash"
    
    # Credenziali API e indirizzi di rete
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

# Istanza globale condivisa (Pattern Singleton) caricata una sola volta all'avvio
settings = Settings()
