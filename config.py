
# config.py

import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load .env once, if present
load_dotenv()


class Settings(BaseSettings):
    # ============================
    # Confluence Configuration
    # ============================
    CONFLUENCE_URL: str = os.getenv("CONFLUENCE_URL", "https://your-domain.atlassian.net")
    CONFLUENCE_USERNAME: str = os.getenv("CONFLUENCE_USERNAME", "")
    CONFLUENCE_API_TOKEN: str = os.getenv("CONFLUENCE_API_TOKEN", "")
    CONFLUENCE_SPACE: str = os.getenv("CONFLUENCE_SPACE", "SOCTEST")

    # ============================
    # Ollama (LLM) Configuration
    # ============================
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL_NAME: str = os.getenv("OLLAMA_MODEL_NAME", "mistral:7b-instruct-v0.2-q4_K_M")
    OLLAMA_NUM_PREDICT: int = int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))

    # Workflow tuning
    DEFAULT_CONCURRENCY: int = int(os.getenv("UC_CONCURRENCY", "5"))
    DEFAULT_BATCH_SIZE: int = int(os.getenv("UC_BATCH_SIZE", "5"))
    ENABLE_BATCH_SLEEP: bool = os.getenv("UC_ENABLE_BATCH_SLEEP", "false").lower() == "true"
    BATCH_SLEEP_SECONDS: float = float(os.getenv("UC_BATCH_SLEEP_SECONDS", "0"))

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

