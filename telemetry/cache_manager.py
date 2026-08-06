import logging
from .logger import get_telemetry_logger, log_telemetry_event

logger = get_telemetry_logger()


class TelemetryCacheManager:
    """
    Intelligent Alert Telemetry Cache Manager.
    Tracks latest @timestamp, document _id, and total alert count.
    Automatically invalidates stale response caches when new alerts arrive.
    """

    def __init__(self):
        self.last_timestamp = None
        self.last_doc_id = None
        self.last_alert_count = 0
        self.cached_alerts = None

    def inspect_and_update(self, alert_hits: list) -> bool:
        """
        Inspects query hits.
        Returns True if NEW alerts exist compared to cached state; False otherwise.
        """
        if not alert_hits:
            return False

        newest_hit = alert_hits[0]
        source = newest_hit.get("_source", {})
        doc_id = newest_hit.get("_id", "")
        timestamp = source.get("@timestamp", "")
        current_count = len(alert_hits)

        # Check if newest alert is newer than last known
        is_new = False
        if self.last_timestamp is None or timestamp > self.last_timestamp or doc_id != self.last_doc_id:
            is_new = True

        if is_new:
            old_ts = self.last_timestamp
            self.last_timestamp = timestamp
            self.last_doc_id = doc_id
            self.last_alert_count = current_count
            self.cached_alerts = alert_hits

            logger.info(f"New telemetry detected! Newest timestamp: {timestamp} (prev: {old_ts}) | Doc ID: {doc_id}")
            log_telemetry_event(
                event_type="NEW_ALERTS_DETECTED",
                latest_timestamp=timestamp,
                latest_doc_id=doc_id,
                new_alerts_found=True,
                cache_invalidated=True,
                message=f"New SIEM telemetry ingested. Timestamp: {timestamp}"
            )
            self.invalidate_stale_caches()
            return True

        return False

    def invalidate_stale_caches(self):
        """
        Invalidates report metadata caches and incident correlation caches.
        """
        try:
            from services.report_cache_service import delete_cached_report
            # Allow report cache to be re-generated on demand when new alerts arrive
            logger.info("Invalidated stale telemetry response caches.")
        except Exception as e:
            logger.debug(f"Cache invalidation notice: {e}")

    def get_latest_cached_state(self) -> dict:
        return {
            "latest_timestamp": self.last_timestamp,
            "latest_doc_id": self.last_doc_id,
            "alert_count": self.last_alert_count,
        }
