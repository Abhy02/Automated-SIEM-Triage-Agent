import math
import logging
from collections import Counter
from services.opensearch_client import get_latest_alerts
from parser.alert_normalizer import normalize
from parser.risk_engine import calculate_risk

logger = logging.getLogger(__name__)

CRITICAL_LEVEL = 12
HIGH_LEVEL = 8
MEDIUM_LEVEL = 5


def get_dashboard_data(page: int = 1, per_page: int = 20, search_query: str = "", severity_filter: str = "all") -> dict:
    """
    Fetch and prepare dashboard telemetry without LLM, MITRE, or enrichment latency.
    Supports KPI aggregation, highest priority advisory selection, and pagination.
    """
    logger.info("Loading telemetry dataset from OpenSearch...")

    try:
        raw_alerts = get_latest_alerts(size=1000)
    except Exception:
        logger.exception("Failed to query OpenSearch alerts.")
        raw_alerts = []

    # 1. Filter dataset by Search and Severity
    filtered_alerts = []
    severity_counter = Counter()
    agents = set()

    highest_priority_raw = None
    highest_severity_level = -1

    for alert in raw_alerts:
        source = alert.get("_source", {})
        doc_id = alert.get("_id", "")
        level = source.get("rule", {}).get("level", 0)
        agent = source.get("agent", {}).get("name", "Unknown")
        description = source.get("rule", {}).get("description", "").lower()
        rule_id = str(source.get("rule", {}).get("id", ""))
        agents.add(agent)

        # Track severity counters
        if level >= CRITICAL_LEVEL:
            sev_cat = "critical"
        elif level >= HIGH_LEVEL:
            sev_cat = "high"
        elif level >= MEDIUM_LEVEL:
            sev_cat = "medium"
        else:
            sev_cat = "low"

        severity_counter[sev_cat] += 1

        # Track highest priority alert for Advisory Banner
        if level > highest_severity_level:
            highest_severity_level = level
            highest_priority_raw = alert

        # Apply search and severity filter for displayed table
        q = search_query.strip().lower()
        match_search = (not q or
                        q in description or
                        q in rule_id or
                        q in agent.lower() or
                        q in doc_id.lower())

        match_severity = (severity_filter == "all" or sev_cat == severity_filter.lower())

        if match_search and match_severity:
            filtered_alerts.append(alert)

    # 2. Pagination calculation
    total_items = len(filtered_alerts)
    total_pages = max(1, math.ceil(total_items / per_page))
    current_page = max(1, min(page, total_pages))
    start_idx = (current_page - 1) * per_page
    end_idx = start_idx + per_page

    paginated_alerts = filtered_alerts[start_idx:end_idx]

    stats = {
        "total": len(raw_alerts),
        "critical": severity_counter["critical"],
        "high": severity_counter["high"],
        "medium": severity_counter["medium"],
        "low": severity_counter["low"],
        "agents": len(agents),
    }

    # Prepare Highest Priority Advisory Preview (Lightweight preview without AI/MITRE enrichment)
    latest_preview = None
    if highest_priority_raw:
        top_source = highest_priority_raw.get("_source", {})
        doc_id = highest_priority_raw.get("_id", "")
        norm_alert = normalize(top_source)
        risk = calculate_risk(top_source)

        latest_preview = {
            "doc_id": doc_id,
            "alert": norm_alert,
            "risk": risk,
            "report": {
                "summary": f"{norm_alert.description} detected on host '{norm_alert.agent_name}'. Highest severity event (Level {norm_alert.severity})."
            }
        }

    return {
        "latest": latest_preview,
        "alerts": paginated_alerts,
        "stats": stats,
        "pagination": {
            "total_items": total_items,
            "total_pages": total_pages,
            "current_page": current_page,
            "per_page": per_page,
            "has_prev": current_page > 1,
            "has_next": current_page < total_pages
        }
    }
