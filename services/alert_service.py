from services.opensearch_client import get_latest_alert
from parser.alert_normalizer import normalize
from parser.ioc_extractor import extract_iocs
from parser.risk_engine import calculate_risk
from threat_intel.intel_engine import enrich_iocs
from mitre.mapper import get_mitre
from ai.incident_analyzer import generate_report


def analyze_latest_alert():
    """
    Fetch the latest alert from OpenSearch, normalize it,
    enrich it with threat intelligence, and calculate the risk score.
    """

    # Get the latest raw alert from OpenSearch
    raw_alert = get_latest_alert()

    if raw_alert is None:
        return None

    # Convert raw JSON into a normalized Alert object
    alert = normalize(raw_alert)

    # Extract IOCs from the original raw JSON
    iocs = extract_iocs(str(alert.raw))

    # Calculate risk using the raw alert
    risk = calculate_risk(alert.raw)

    # Map rule ID to MITRE ATT&CK technique(s)
    mitre = get_mitre(alert.rule_id)

    # Enrich IOCs with VirusTotal (and future Threat Intelligence sources)
    intel = enrich_iocs(iocs)

    # Generate AI incident report
    report = generate_report(
        alert,
        risk,
        mitre,
        intel
    )

    return {
        "alert": alert,
        "iocs": iocs,
        "risk": risk,
        "intel": intel,
        "mitre": mitre,
        "report": report,
    }
