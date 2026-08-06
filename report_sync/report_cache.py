import json
import logging
import os
from datetime import datetime
from services.report_cache_service import (
    cache_report,
    get_cached_report,
    delete_cached_report,
    list_all_cached_reports,
    CACHE_DIR,
)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
REPORT_LOG_FILE = os.path.join(LOGS_DIR, "report_sync.log")

_ensure_logs_dir = lambda: os.makedirs(LOGS_DIR, exist_ok=True)


def get_report_sync_logger():
    _ensure_logs_dir()
    logger = logging.getLogger("ReportSync.Cache")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(REPORT_LOG_FILE)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] [ReportSync] %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.propagate = True
    return logger


logger = get_report_sync_logger()


class ReportCacheManager:
    """
    Manages intelligent report caching, status classification (Latest, Outdated, Cached, New Alert),
    smart duplicate detection, and metadata synchronization logging.
    Combines disk-cached reports with live SIEM alerts so all incoming alerts are indexable and actionable.
    """

    def __init__(self):
        self.report_statuses = {}  # doc_id -> status dict
        self.evidence_hashes = {}  # doc_id -> hash string

    def classify_status(self, report_data: dict, has_newer_evidence: bool = False) -> str:
        if has_newer_evidence:
            return "Outdated"
        return "Latest"

    def update_report_status(self, doc_id: str, new_status: str, reason: str = None):
        now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S IST")
        self.report_statuses[doc_id] = {
            "status": new_status,
            "last_updated": now_ts,
            "reason": reason or "Status updated",
        }
        logger.info(f"Report Updated | doc_id: {doc_id} | status: {new_status} | reason: {reason or 'N/A'}")

    def mark_outdated_if_evidence_changed(self, doc_id: str, current_evidence_hash: str) -> bool:
        cached = get_cached_report(doc_id)
        if not cached:
            return False

        prev_hash = self.evidence_hashes.get(doc_id) or cached.get("evidence_hash")
        if prev_hash and prev_hash != current_evidence_hash:
            self.update_report_status(
                doc_id,
                "Outdated",
                reason="New alert data available (Alert/Risk/IOC/MITRE changed)"
            )
            return True
        return False

    def get_report_with_metadata(self, doc_id: str) -> dict:
        report_data = get_cached_report(doc_id)
        if report_data:
            logger.info(f"Cache Hit | doc_id: {doc_id}")
            status_info = self.report_statuses.get(doc_id, {})
            status_val = status_info.get("status", "Cached")
            
            report_data["report_status"] = status_val
            report_data["is_outdated"] = (status_val == "Outdated")
            report_data["outdated_message"] = (
                "⚠ New alert data available. Regenerate Report"
                if status_val == "Outdated"
                else None
            )
            return report_data

        logger.info(f"Cache Miss | doc_id: {doc_id}")
        return None

    def store_cached_report(self, doc_id: str, report_data: dict, evidence_hash: str = None, is_regeneration: bool = False):
        if evidence_hash:
            report_data["evidence_hash"] = evidence_hash
            self.evidence_hashes[doc_id] = evidence_hash

        status = "Latest"
        report_data["report_status"] = status
        self.update_report_status(doc_id, status, reason="Generated" if not is_regeneration else "Regenerated")

        filepath = cache_report(doc_id, report_data)

        action_event = "Report Regenerated" if is_regeneration else "Report Generated"
        logger.info(f"{action_event} | doc_id: {doc_id} | file: {filepath}")
        return filepath

    def get_all_reports_enhanced(self) -> list:
        """
        Returns all cached reports extended with categorization metadata and
        merges newly received SIEM alerts from OpenSearch / Wazuh / Demo Mode
        so users can view and generate reports for all incoming alerts.
        """
        raw_reports = list_all_cached_reports()
        cached_doc_ids = set()
        enhanced = []

        for item in raw_reports:
            doc_id = item.get("doc_id")
            cached_doc_ids.add(doc_id)
            cached_data = get_cached_report(doc_id) or {}
            
            status_meta = self.report_statuses.get(doc_id, {})
            status_val = status_meta.get("status", cached_data.get("report_status", "Cached"))

            item["status"] = status_val
            item["is_generated"] = True
            item["is_outdated"] = (status_val == "Outdated")
            item["outdated_message"] = "⚠ New alert data available. Regenerate Report" if status_val == "Outdated" else None
            item["generated_at"] = cached_data.get("generated_at", item.get("created_at"))
            item["last_alert_timestamp"] = cached_data.get("alert", {}).get("timestamp") or item.get("created_at")

            enhanced.append(item)

        # Merge live incoming SIEM alerts from OpenSearch / Wazuh / Demo Mode
        try:
            from services.opensearch_client import get_latest_alerts
            from dashboard.utils import format_timestamp, severity_badge

            live_hits = get_latest_alerts(size=100)
            for hit in live_hits:
                doc_id = hit.get("_id")
                if not doc_id or doc_id in cached_doc_ids:
                    continue

                source = hit.get("_source", {})
                raw_ts = source.get("@timestamp", "")
                rule = source.get("rule", {})
                rule_level = rule.get("level", 0)
                rule_id = rule.get("id", "N/A")
                desc = rule.get("description", "No description")
                agent = source.get("agent", {})
                agent_name = agent.get("name", "Unknown")
                risk_lvl = severity_badge(rule_level)

                enhanced.append({
                    "doc_id": doc_id,
                    "created_at": format_timestamp(raw_ts),
                    "rule_id": rule_id,
                    "severity": rule_level,
                    "agent_name": agent_name,
                    "risk": risk_lvl,
                    "summary": f"Alert rule #{rule_id} ({desc}) detected on host '{agent_name}'. Click Generate to produce AI Investigation Report.",
                    "mitre_technique": "TBD",
                    "status": "New Alert",
                    "is_generated": False,
                    "is_outdated": False,
                    "outdated_message": None,
                    "generated_at": None,
                    "last_alert_timestamp": format_timestamp(raw_ts),
                })
                cached_doc_ids.add(doc_id)
        except Exception as e:
            logger.error(f"Error merging live SIEM alerts into reports index: {e}")

        # Sort by created_at descending
        enhanced.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return enhanced
