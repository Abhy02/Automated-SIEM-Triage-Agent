import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def check_ip(ip: str) -> dict:
    """
    Query VirusTotal v3 API for IP reputation, community score, ASN, and analysis.
    """
    if not API_KEY:
        return {
            "status": "unconfigured",
            "message": "VirusTotal API key not configured.",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "community_score": 0,
            "ref_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(BASE_URL + ip, headers=headers, timeout=10)
        if response.status_code != 200:
            return {
                "error": f"HTTP {response.status_code}",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "community_score": 0,
                "ref_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }

        data = response.json().get("data", {})
        attr = data.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "community_score": attr.get("reputation", 0),
            "asn": attr.get("asn", "N/A"),
            "as_owner": attr.get("as_owner", "N/A"),
            "country": attr.get("country", "N/A"),
            "network": attr.get("network", "N/A"),
            "ref_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    except Exception as e:
        return {
            "error": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "community_score": 0,
            "ref_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
