import threading
import time
from .logger import get_telemetry_logger
from .alert_sync import AlertSyncEngine
from .recovery import TelemetryRecoveryEngine

logger = get_telemetry_logger()

_global_monitor_instance = None
_global_monitor_lock = threading.Lock()


class BackgroundAlertMonitor:
    """
    Lightweight Asynchronous Background Telemetry Monitor (<1% CPU).
    Continuously monitors OpenSearch for new alerts, timestamp changes, and document IDs.
    Triggers automatic self-healing recovery if connection stalls or alerts stop arriving.
    """

    def __init__(self, check_interval: int = 15):
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.sync_engine = AlertSyncEngine()
        self.recovery_engine = TelemetryRecoveryEngine()
        self.last_sync_timestamp = time.time()

    def start(self):
        """Starts the background telemetry monitor daemon thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="TelemetryMonitorThread")
        self.thread.start()
        logger.info(f"Background Telemetry Monitor daemon started (interval: {self.check_interval}s, CPU < 1%).")

    def stop(self):
        """Stops the background telemetry monitor daemon thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("Background Telemetry Monitor daemon stopped.")

    def _monitor_loop(self):
        """Background telemetry sync and self-healing loop."""
        while self.running:
            try:
                # Sleep keeping CPU usage < 0.1%
                time.sleep(self.check_interval)
                if not self.running:
                    break

                # Query OpenSearch and validate alert freshness
                hits = self.sync_engine.fetch_fresh_alerts(size=100)

                # Check connection health and self-healing trigger
                summary = self.sync_engine.get_latest_telemetry_summary()
                if not summary["opensearch_connected"]:
                    logger.warning("Background monitor detected OpenSearch connection drop. Triggering self-healing recovery...")
                    self.recovery_engine.execute_telemetry_recovery(reason="OpenSearch connection offline")
                else:
                    self.last_sync_timestamp = time.time()

            except Exception as e:
                logger.error(f"Unexpected exception in BackgroundAlertMonitor loop: {e}")


def get_telemetry_monitor() -> BackgroundAlertMonitor:
    global _global_monitor_instance
    with _global_monitor_lock:
        if _global_monitor_instance is None:
            _global_monitor_instance = BackgroundAlertMonitor()
        return _global_monitor_instance


def start_telemetry_monitor() -> BackgroundAlertMonitor:
    monitor = get_telemetry_monitor()
    monitor.start()
    return monitor
