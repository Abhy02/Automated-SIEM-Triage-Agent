import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/"


def check_otx_pulse(ip: str) -> dict:
    """
    Query AlienVault OTX for IP threat pulses and malware indicators.
    """
    if not API_KEY:
        return {
            "status": "unconfigured",
            "message": "AlienVault OTX API key not set.",
            "pulse_count": 0
        }

    headers = {
        "X-OTX-API-KEY": API_KEY
    }

    try:
        response = requests.get(f"{BASE_URL}{ip}/general", headers=headers, timeout=10)
        if response.status_code != 200:
            return {
                "error": f"HTTP {response.status_code}",
                "pulse_count": 0
            }

        data = response.json()
        pulse_info = data.get("pulse_info", {})
        return {
            "ip": ip,
            "pulse_count": pulse_info.get("count", 0),
            "reputation": data.get("reputation", 0),
            "country": data.get("country_name", "Unknown")
        }
    except Exception as e:
        return {
            "error": str(e),
            "pulse_count": 0
        }
