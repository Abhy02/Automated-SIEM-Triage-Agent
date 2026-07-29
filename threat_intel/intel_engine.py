from threat_intel.virustotal import check_ip as vt_check_ip
from threat_intel.abuseipdb import check_ip_reputation as abuseipdb_check_ip
from threat_intel.otx import check_otx_pulse


def enrich_iocs(iocs: dict) -> list:
    """
    Enrich extracted network IOCs across VirusTotal, AbuseIPDB, and AlienVault OTX.
    """
    results = []

    for ip_item in iocs.get("ips", []):
        ip = ip_item.get("ip")
        ip_type = ip_item.get("type", "Unknown")

        if ip_type == "Public":
            vt_res = vt_check_ip(ip)
            abuse_res = abuseipdb_check_ip(ip)
            otx_res = check_otx_pulse(ip)

            results.append({
                "ip": ip,
                "type": ip_type,
                "virustotal": vt_res,
                "abuseipdb": abuse_res,
                "otx": otx_res
            })

    return results
