import logging
from services.investigation_context_builder import build_investigation_context
from ai.incident_analyzer import generate_report_from_context
from services.report_cache_service import cache_report, get_cached_report

logger = logging.getLogger(__name__)


def investigate_alert(doc_id: str, force_refresh: bool = False) -> dict:
    """
    Performs complete evidence-first investigation for an alert document ID.
    Utilizes InvestigationContextBuilder as single source of truth.
    Caches results to prevent redundant LLM calls.
    """
    if not force_refresh:
        cached = get_cached_report(doc_id)
        if cached:
            logger.info("Serving cached evidence report for doc_id: %s", doc_id)
            return cached

    # Build full evidence context payload
    context = build_investigation_context(doc_id)
    if not context:
        return None

    # Generate evidence-grounded AI incident report
    report = generate_report_from_context(context)

    result = {
        "doc_id": doc_id,
        "alert": {
            "timestamp": context["alert"]["timestamp"],
            "rule_id": context["alert"]["rule_id"],
            "severity": context["alert"]["rule_level"],
            "description": context["alert"]["rule_description"],
            "agent_name": context["host"]["agent_name"],
            "agent_ip": context["host"]["agent_ip"],
            "location": context["alert"]["location"],
            "full_log": context["alert"]["full_log"]
        },
        "risk": context["risk"]["risk_score"],
        "iocs": context["iocs"],
        "intel": context["threat_intelligence"],
        "mitre": context["mitre"],
        "history": context["history"],
        "correlation": context["correlation"],
        "report": report
    }

    cache_report(doc_id, result)
    return result
