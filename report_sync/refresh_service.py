import logging
import threading
import time
from datetime import datetime

from .report_monitor import ReportMonitor
from .report_cache import ReportCacheManager
from .report_generator import ReportGenerator

logger = logging.getLogger("ReportSync.Service")

_global_sync_instance = None
_global_sync_lock = threading.Lock()


class ReportRefreshService:
    """
    Asynchronous Report Synchronization Engine.
    Periodically checks the latest SIEM alert index, refreshes report metadata and status,
    and flags outdated reports without blocking main routes, AI analysis, or OpenSearch queries.
    """

    def __init__(self, check_interval: int = 15):
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.monitor = ReportMonitor()
        self.cache_manager = ReportCacheManager()
        self.generator = ReportGenerator(self.cache_manager)
        self.last_sync_time = None
        self.stats = {
            "total_alerts_seen": 0,
            "outdated_reports": 0,
            "cached_reports": 0,
            "latest_reports": 0,
            "last_alert_timestamp": None,
        }

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._sync_loop, daemon=True, name="ReportSyncThread")
        self.thread.start()
        logger.info(f"ReportRefreshService daemon started (interval: {self.check_interval}s).")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("ReportRefreshService daemon stopped.")

    def sync_now(self):
        """
        Executes immediate alert index scan and report status refresh.
        Never regenerates reports automatically for every alert; only updates status & metadata.
        """
        try:
            scan_res = self.monitor.scan_for_alerts()
            new_alerts = scan_res.get("new_alerts", [])
            updated_alerts = scan_res.get("updated_alerts", [])

            self.stats["last_alert_timestamp"] = scan_res.get("last_timestamp")
            self.stats["total_alerts_seen"] = scan_res.get("total_count", 0)

            # Process updated alerts to mark corresponding cached reports as Outdated
            for hit in updated_alerts:
                doc_id = hit.get("_id")
                curr_hash = self.monitor.compute_alert_hash(hit)
                if doc_id:
                    self.cache_manager.mark_outdated_if_evidence_changed(doc_id, curr_hash)

            # Update aggregated stats
            all_reps = self.cache_manager.get_all_reports_enhanced()
            outdated_cnt = sum(1 for r in all_reps if r.get("is_outdated"))
            latest_cnt = sum(1 for r in all_reps if r.get("status") == "Latest")
            cached_cnt = sum(1 for r in all_reps if r.get("status") == "Cached")

            self.stats["outdated_reports"] = outdated_cnt
            self.stats["latest_reports"] = latest_cnt
            self.stats["cached_reports"] = cached_cnt
            self.last_sync_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S IST")

            logger.info(
                f"Report Index Refresh completed | Total Alerts: {self.stats['total_alerts_seen']} | "
                f"New: {len(new_alerts)} | Updated: {len(updated_alerts)} | "
                f"Outdated Reports: {outdated_cnt} | Latest Reports: {latest_cnt} | Cached: {cached_cnt}"
            )
            return self.stats
        except Exception as e:
            logger.error(f"Error during report synchronization: {e}")
            return self.stats

    def _sync_loop(self):
        # Initial sync on startup
        try:
            self.sync_now()
        except Exception as e:
            logger.error(f"Error during initial report sync: {e}")

        while self.running:
            try:
                time.sleep(self.check_interval)
                if self.running:
                    self.sync_now()
            except Exception as e:
                logger.error(f"Unexpected error in ReportRefreshService loop: {e}")


def get_report_sync():
    global _global_sync_instance
    with _global_sync_lock:
        if _global_sync_instance is None:
            _global_sync_instance = ReportRefreshService()
        return _global_sync_instance


def start_report_sync():
    sync_service = get_report_sync()
    sync_service.start()
    return sync_service
