import logging
from .logger import get_telemetry_logger, log_telemetry_event
from .connection_manager import TelemetryConnectionManager
from .cache_manager import TelemetryCacheManager

logger = get_telemetry_logger()


class AlertSyncEngine:
    """
    Enterprise Alert Telemetry Synchronization Controller.
    Queries OpenSearch, validates alert freshness (@timestamp, _id),
    updates cache state, and returns fresh SIEM alerts to the platform.
    """

    def __init__(self):
        self.conn_mgr = TelemetryConnectionManager()
        self.cache_mgr = TelemetryCacheManager()

    def fetch_fresh_alerts(self, size: int = 100) -> list:
        """
        Fetches fresh alerts from OpenSearch, validating connectivity and freshness.
        """
        from services.opensearch_client import get_latest_alerts

        # Verify OpenSearch connection before query
        if not self.conn_mgr.verify_opensearch():
            logger.warning("OpenSearch connection unverified during sync check. Attempting reconnect...")
            self.conn_mgr.reconnect_opensearch_client()

        try:
            hits = get_latest_alerts(size=size)
            if hits:
                new_found = self.cache_mgr.inspect_and_update(hits)
                log_telemetry_event(
                    event_type="ALERT_REFRESH",
                    opensearch_connected=True,
                    latest_timestamp=self.cache_mgr.last_timestamp,
                    latest_doc_id=self.cache_mgr.last_doc_id,
                    new_alerts_found=new_found,
                    message=f"Retrieved {len(hits)} alerts from OpenSearch"
                )
                return hits
        except Exception as e:
            logger.error(f"Error fetching fresh alerts during telemetry sync: {e}")
            self.conn_mgr.reconnect_opensearch_client()

        return []

    def get_latest_telemetry_summary(self) -> dict:
        state = self.cache_mgr.get_latest_cached_state()
        opensearch_ok = self.conn_mgr.verify_opensearch()
        wazuh_ok = self.conn_mgr.verify_wazuh_api()

        return {
            "opensearch_connected": opensearch_ok,
            "wazuh_api_connected": wazuh_ok,
            "latest_timestamp": state.get("latest_timestamp"),
            "latest_doc_id": state.get("latest_doc_id"),
            "alert_count": state.get("alert_count"),
        }
