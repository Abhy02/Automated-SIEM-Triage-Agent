import logging
from services.opensearch_client import get_latest_alerts
from services.report_cache_service import list_all_cached_reports

logger = logging.getLogger(__name__)


def global_search(query: str) -> dict:
    """
    Search across OpenSearch SIEM alerts, saved report archives, and agents.
    """
    query_str = (query or "").strip().lower()
    if not query_str:
        return {"alerts": [], "reports": [], "total": 0}

    # Search OpenSearch Alerts
    matched_alerts = []
    try:
        alerts = get_latest_alerts(size=50)
        for alert in alerts:
            source = alert.get("_source", {})
            doc_id = alert.get("_id", "")
            description = source.get("rule", {}).get("description", "").lower()
            rule_id = str(source.get("rule", {}).get("id", ""))
            agent_name = source.get("agent", {}).get("name", "").lower()
            agent_ip = source.get("agent", {}).get("ip", "").lower()

            if (query_str in description or
                query_str in rule_id or
                query_str in agent_name or
                query_str in agent_ip or
                query_str in doc_id.lower()):
                matched_alerts.append({
                    "doc_id": doc_id,
                    "rule_id": rule_id,
                    "description": source.get("rule", {}).get("description", ""),
                    "agent_name": source.get("agent", {}).get("name", ""),
                    "agent_ip": source.get("agent", {}).get("ip", ""),
                    "timestamp": source.get("@timestamp", "")
                })
    except Exception as e:
        logger.error("Global search OpenSearch query failed: %s", str(e))

    # Search Saved Reports
    matched_reports = []
    try:
        cached = list_all_cached_reports()
        for rep in cached:
            summary = rep.get("summary", "").lower()
            rule_id = str(rep.get("rule_id", ""))
            doc_id = rep.get("doc_id", "").lower()
            agent_name = rep.get("agent_name", "").lower()

            if (query_str in summary or
                query_str in rule_id or
                query_str in doc_id or
                query_str in agent_name):
                matched_reports.append(rep)
    except Exception as e:
        logger.error("Global search reports query failed: %s", str(e))

    return {
        "query": query,
        "alerts": matched_alerts,
        "reports": matched_reports,
        "total": len(matched_alerts) + len(matched_reports)
    }
