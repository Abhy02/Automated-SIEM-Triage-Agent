import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "aisoc-enterprise-secret-key-prod-2026-v4")
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
    
    # SIEM Configuration
    WAZUH_HOST = os.getenv("WAZUH_HOST", "https://192.168.1.61:55000")
    WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
    WAZUH_PASS = os.getenv("WAZUH_PASS", "")

    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", os.getenv("INDEXER_HOST", "https://192.168.1.61:9200"))
    OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", os.getenv("INDEXER_USERNAME", "admin"))
    OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", os.getenv("INDEXER_PASSWORD", "SecretPassword"))

    # Ollama Local LLM Configuration
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

    # Threat Intelligence API Keys
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
