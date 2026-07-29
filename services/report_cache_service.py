import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "cache")
_MEMORY_CACHE = {}


def cache_report(doc_id: str, report_data: dict) -> str:
    """
    Persist investigation report in memory and disk cache.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    _MEMORY_CACHE[doc_id] = report_data

    filepath = os.path.join(CACHE_DIR, f"{doc_id}.json")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        logger.info("Persisted report cache for doc_id: %s to %s", doc_id, filepath)
    except Exception as e:
        logger.error("Failed to write report disk cache for %s: %s", doc_id, str(e))

    return filepath


def get_cached_report(doc_id: str) -> dict:
    """
    Retrieve cached report from memory or disk. Returns None if cache miss.
    """
    if doc_id in _MEMORY_CACHE:
        return _MEMORY_CACHE[doc_id]

    filepath = os.path.join(CACHE_DIR, f"{doc_id}.json")
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                _MEMORY_CACHE[doc_id] = data
                return data
        except Exception as e:
            logger.error("Failed to read report disk cache for %s: %s", doc_id, str(e))

    return None


def delete_cached_report(doc_id: str) -> bool:
    """
    Delete report from memory and disk cache.
    """
    _MEMORY_CACHE.pop(doc_id, None)
    filepath = os.path.join(CACHE_DIR, f"{doc_id}.json")
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return True
        except Exception as e:
            logger.error("Failed to delete report cache for %s: %s", doc_id, str(e))
    return False


def list_all_cached_reports() -> list:
    """
    List all cached reports stored on disk.
    """
    if not os.path.exists(CACHE_DIR):
        return []

    reports = []
    for fn in sorted(os.listdir(CACHE_DIR), reverse=True):
        if fn.endswith(".json"):
            doc_id = fn.replace(".json", "")
            data = get_cached_report(doc_id)
            if data:
                alert = data.get("alert", {})
                report = data.get("report", {})
                reports.append({
                    "doc_id": doc_id,
                    "created_at": alert.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
                    "rule_id": alert.get("rule_id", "N/A"),
                    "severity": alert.get("severity", 0),
                    "agent_name": alert.get("agent_name", "Unknown"),
                    "risk": data.get("risk", "Low"),
                    "summary": report.get("summary", ""),
                    "mitre_technique": data.get("mitre", {}).get("technique", "N/A")
                })
    return reports
