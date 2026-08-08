import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "BitM Sentinel Engine"
    API_PREFIX: str = "/api/v1"
    
    # Provider predefinito e modello LLM
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemini-2.0-flash")
    
    # Keys & Endpoints
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
