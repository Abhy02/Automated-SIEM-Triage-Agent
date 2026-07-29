import re
import ipaddress

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"
HASH_REGEX = (
    r"\b[a-fA-F0-9]{32}\b|"
    r"\b[a-fA-F0-9]{40}\b|"
    r"\b[a-fA-F0-9]{64}\b"
)
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"


def classify_ip(ip):
    ip_obj = ipaddress.ip_address(ip)

    if ip == "0.0.0.0":
        return "Wildcard"

    if ip_obj.is_loopback:
        return "Loopback"

    if ip_obj.is_private:
        return "Private"

    if ip_obj.is_multicast:
        return "Multicast"

    if ip_obj.is_reserved:
        return "Reserved"

    return "Public"


def extract_iocs(text):
    ips = sorted(set(re.findall(IP_REGEX, text)))
    classified_ips = []
    for ip in ips:
        classified_ips.append({
            "ip": ip,
            "type": classify_ip(ip)
        })
    return {
        "ips": classified_ips,
        "hashes": sorted(set(re.findall(HASH_REGEX, text))),
        "domains": sorted(set(re.findall(DOMAIN_REGEX, text))),
        "urls": sorted(set(re.findall(URL_REGEX, text))),
    }
