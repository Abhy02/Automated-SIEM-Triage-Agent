import logging
from services.opensearch_client import get_alert_by_document_id, get_latest_alerts
from parser.alert_normalizer import normalize
from parser.ioc_extractor import extract_iocs
from parser.risk_engine import calculate_risk
from threat_intel.intel_engine import enrich_iocs
from mitre.mapper import get_mitre
from services.correlation_engine import correlate_incident

logger = logging.getLogger(__name__)


def build_investigation_context(doc_id: str) -> dict:
    """
    Single Source of Truth Evidence Collection Pipeline.
    Collects complete telemetry, host metadata, historical frequency,
    full raw logs, IOCs, Threat Intel, MITRE mappings, and correlation.
    """
    raw_alert = get_alert_by_document_id(doc_id)
    if not raw_alert:
        return None

    # Step 1: Alert Normalization & Raw Log Extraction
    norm_alert = normalize(raw_alert)
    full_log = raw_alert.get("full_log", raw_alert.get("previous_output", norm_alert.description))
    rule = raw_alert.get("rule", {})
    agent = raw_alert.get("agent", {})
    decoder = raw_alert.get("decoder", {})

    alert_context = {
        "doc_id": doc_id,
        "timestamp": norm_alert.timestamp,
        "rule_id": str(norm_alert.rule_id),
        "rule_level": norm_alert.severity,
        "rule_description": norm_alert.description,
        "rule_groups": rule.get("groups", []),
        "decoder_name": decoder.get("name", "ossec"),
        "full_log": full_log,
        "location": norm_alert.location,
        "manager_name": raw_alert.get("manager", {}).get("name", "wazuh.manager")
    }

    # Step 2: Host Context
    host_context = {
        "agent_name": norm_alert.agent_name,
        "agent_id": agent.get("id", "001"),
        "agent_ip": norm_alert.agent_ip,
        "hostname": raw_alert.get("predecoder", {}).get("hostname", norm_alert.agent_name),
        "os_name": agent.get("os", {}).get("name", "Linux")
    }

    # Step 3: Historical Context (OpenSearch Alert Frequencies)
    recent_alerts = get_latest_alerts(size=30)
    same_rule_count = 0
    same_agent_count = 0

    for item in recent_alerts:
        src = item.get("_source", {})
        if str(src.get("rule", {}).get("id")) == str(norm_alert.rule_id):
            same_rule_count += 1
        if src.get("agent", {}).get("name") == norm_alert.agent_name:
            same_agent_count += 1

    history_context = {
        "same_rule_occurrences_recent": same_rule_count,
        "same_agent_occurrences_recent": same_agent_count,
        "recent_alert_volume": len(recent_alerts),
        "frequency_trend": "High Frequency" if same_rule_count > 3 else "Isolated Event"
    }

    # Step 4: IOC Extraction & Threat Intel Enrichment
    extracted_iocs = extract_iocs(str(raw_alert))
    intel_results = enrich_iocs(extracted_iocs)

    # Step 5: MITRE ATT&CK Mapping
    mitre_data = get_mitre(norm_alert.rule_id)
    mitre_context = {
        "technique": mitre_data.get("technique", "Unknown"),
        "name": mitre_data.get("name", "Unknown"),
        "tactic": mitre_data.get("tactic", "Unknown"),
        "mapping_reasoning": f"Wazuh rule #{norm_alert.rule_id} matches behavior classified under TTP {mitre_data.get('technique')}"
    }

    # Step 6: Incident Correlation & Attack Story
    correlation_data = correlate_incident(doc_id)

    # Step 7: Risk Assessment & False Positive Estimation
    calculated_risk = calculate_risk(raw_alert)
    fp_prob = "Low" if norm_alert.severity >= 8 else ("Medium" if norm_alert.severity >= 5 else "High")

    risk_context = {
        "risk_score": calculated_risk,
        "rule_level": norm_alert.severity,
        "false_positive_probability": fp_prob,
        "reasoning": f"Derived from Wazuh rule level {norm_alert.severity} and host event volume ({same_rule_count} occurrences)."
    }

    return {
        "alert": alert_context,
        "host": host_context,
        "history": history_context,
        "iocs": extracted_iocs,
        "threat_intelligence": intel_results,
        "mitre": mitre_context,
        "correlation": correlation_data,
        "risk": risk_context
    }
