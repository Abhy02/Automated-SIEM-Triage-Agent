import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip: str) -> dict:
    """
    Query AbuseIPDB API v2 for IP reputation and abuse score.
    """
    if not API_KEY:
        return {
            "status": "unconfigured",
            "message": "AbuseIPDB API key not set in environment.",
            "abuse_score": 0,
            "reports": 0
        }

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(URL, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return {
                "error": f"HTTP {response.status_code}",
                "abuse_score": 0,
                "reports": 0
            }

        data = response.json().get("data", {})
        return {
            "ip": data.get("ipAddress", ip),
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "is_whitelisted": data.get("isWhitelisted", False)
        }
    except Exception as e:
        return {
            "error": str(e),
            "abuse_score": 0,
            "reports": 0
        }
