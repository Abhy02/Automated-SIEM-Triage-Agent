import logging
from datetime import datetime
from services.investigation_service import investigate_alert
from .report_cache import ReportCacheManager

logger = logging.getLogger("ReportSync.Generator")


class ReportGenerator:
    """
    Intelligent Report Generation Engine.
    Handles demand-driven report creation and metadata synchronization without auto-generating PDFs for every alert.
    """

    def __init__(self, cache_manager: ReportCacheManager = None):
        self.cache_manager = cache_manager or ReportCacheManager()
        self.generation_queue = []

    def queue_report_request(self, doc_id: str, priority: bool = False):
        """
        Adds a report generation request to queue if not already queued.
        """
        if doc_id not in self.generation_queue:
            if priority:
                self.generation_queue.insert(0, doc_id)
            else:
                self.generation_queue.append(doc_id)
            logger.info(f"Queued report generation request for doc_id: {doc_id}")

    def generate_or_get_report(self, doc_id: str, force_regenerate: bool = False, evidence_hash: str = None) -> dict:
        """
        Generates a fresh investigation report or returns cached report if identical evidence exists.

        Updates Metadata:
        - Alert Count
        - Risk Score
        - MITRE Mapping
        - Threat Intelligence
        - IOC List
        - Timeline
        - Evidence
        """
        # 1. Smart Duplicate Check: If not forcing regenerate, check if valid non-outdated cache exists
        if not force_regenerate:
            existing = self.cache_manager.get_report_with_metadata(doc_id)
            if existing and not existing.get("is_outdated"):
                logger.info(f"Smart Duplicate Protection: Reusing cached report for doc_id {doc_id}")
                return existing

        # 2. Run fresh AI investigation and metadata synthesis
        logger.info(f"Generating fresh investigation report metadata for doc_id: {doc_id} (Force: {force_regenerate})")
        report_data = investigate_alert(doc_id, force_refresh=True)

        if not report_data:
            logger.error(f"Failed to generate report data for alert doc_id: {doc_id}")
            return None

        # 3. Decorate metadata timestamp & metadata refresh attributes
        report_data["generated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        report_data["metadata_refreshed_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S IST")

        # Ensure all required metadata elements are present
        alert_info = report_data.get("alert", {})
        report_data["alert_count"] = report_data.get("alert_count", 1)
        report_data["risk_score"] = report_data.get("risk", "Low")
        report_data["mitre_mapping"] = report_data.get("mitre", {})
        report_data["threat_intel"] = report_data.get("intel", {})
        report_data["ioc_list"] = report_data.get("iocs", [])
        report_data["timeline"] = report_data.get("report", {}).get("timeline", [])
        report_data["evidence"] = {
            "source_ip": alert_info.get("src_ip"),
            "agent_name": alert_info.get("agent_name"),
            "agent_ip": alert_info.get("agent_ip"),
            "rule_id": alert_info.get("rule_id"),
            "description": alert_info.get("description"),
            "full_log": alert_info.get("full_log")
        }

        # 4. Save into cache store with evidence hash & log action
        self.cache_manager.store_cached_report(
            doc_id=doc_id,
            report_data=report_data,
            evidence_hash=evidence_hash,
            is_regeneration=force_regenerate
        )

        return report_data
