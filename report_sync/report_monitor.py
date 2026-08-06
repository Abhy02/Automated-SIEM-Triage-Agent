import hashlib
import json
import logging
from datetime import datetime
from services.dashboard_service import get_dashboard_data
from services.opensearch_client import get_latest_alerts

logger = logging.getLogger("ReportSync.Monitor")


class ReportMonitor:
    """
    Monitors incoming SIEM alerts from OpenSearch, Wazuh, or Demo Mode.
    Detects new alerts and tracks alert content mutations without repeated processing.
    """

    def __init__(self):
        self.seen_doc_ids = set()
        self.doc_hashes = {}
        self.last_alert_timestamp = None
        self.total_alerts_detected = 0

    def compute_alert_hash(self, alert_hit: dict) -> str:
        """
        Compute SHA-256 fingerprint hash of alert content to detect updates in evidence or metadata.
        """
        source = alert_hit.get("_source", {})
        payload = {
            "doc_id": alert_hit.get("_id", ""),
            "timestamp": source.get("@timestamp", ""),
            "rule_id": source.get("rule", {}).get("id"),
            "rule_level": source.get("rule", {}).get("level"),
            "agent_name": source.get("agent", {}).get("name"),
            "agent_ip": source.get("agent", {}).get("ip"),
            "data": source.get("data", {}),
            "description": source.get("rule", {}).get("description"),
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def scan_for_alerts(self):
        """
        Scans SIEM alert stream for newly received or updated alerts.

        Returns:
            dict: {
                "new_alerts": list of hits,
                "updated_alerts": list of hits,
                "last_timestamp": str,
                "total_count": int
            }
        """
        try:
            data = get_dashboard_data(page=1, per_page=50)
            alerts = data.get("alerts", [])
        except Exception as e:
            logger.error(f"Error fetching dashboard alert data for report monitoring: {e}")
            alerts = []

        new_alerts = []
        updated_alerts = []

        for hit in alerts:
            doc_id = hit.get("_id")
            if not doc_id:
                continue

            current_hash = self.compute_alert_hash(hit)
            source = hit.get("_source", {})
            ts = source.get("@timestamp")

            if ts:
                if not self.last_alert_timestamp or ts > self.last_alert_timestamp:
                    self.last_alert_timestamp = ts

            if doc_id not in self.seen_doc_ids:
                self.seen_doc_ids.add(doc_id)
                self.doc_hashes[doc_id] = current_hash
                new_alerts.append(hit)
                self.total_alerts_detected += 1
            else:
                prev_hash = self.doc_hashes.get(doc_id)
                if prev_hash != current_hash:
                    self.doc_hashes[doc_id] = current_hash
                    updated_alerts.append(hit)

        return {
            "new_alerts": new_alerts,
            "updated_alerts": updated_alerts,
            "last_timestamp": self.last_alert_timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S IST"),
            "total_count": len(self.seen_doc_ids)
        }
