import time
from .logger import get_telemetry_logger, log_telemetry_event
from .connection_manager import TelemetryConnectionManager
from .cache_manager import TelemetryCacheManager

logger = get_telemetry_logger()


class TelemetryRecoveryEngine:
    """
    Network-Aware Self-Healing Telemetry Recovery Engine.
    Handles network switches (Wi-Fi, Ethernet, Hotspot, Sleep/Resume, Docker reconnects).
    Automatically reconnects OpenSearch, Wazuh API, flushes stale cache, and resumes live alert flow.
    """

    def __init__(self):
        self.conn_mgr = TelemetryConnectionManager()
        self.cache_mgr = TelemetryCacheManager()

    def execute_telemetry_recovery(self, reason: str = "Self-Healing Triggered") -> dict:
        """
        Executes non-blocking self-healing telemetry recovery sequence.
        """
        logger.info(f"Initiating telemetry self-healing recovery sequence. Reason: {reason}")
        log_telemetry_event(
            event_type="RECOVERY_TRIGGERED",
            recovery_triggered=True,
            recovery_successful=False,
            message=reason
        )

        opensearch_reconnected = False
        wazuh_api_reconnected = False

        # 1. Reconnect OpenSearch Client
        opensearch_reconnected = self.conn_mgr.reconnect_opensearch_client()

        # 2. Reconnect Wazuh API
        wazuh_api_reconnected = self.conn_mgr.reconnect_wazuh_api()

        # 3. Invalidate Stale Response Cache
        self.cache_mgr.invalidate_stale_caches()

        # 4. Verify post-recovery connectivity
        opensearch_ok = self.conn_mgr.verify_opensearch()
        wazuh_api_ok = self.conn_mgr.verify_wazuh_api()

        success = opensearch_ok or opensearch_reconnected

        log_telemetry_event(
            event_type="RECOVERY_COMPLETED",
            opensearch_connected=opensearch_ok,
            wazuh_api_connected=wazuh_api_ok,
            recovery_triggered=True,
            recovery_successful=success,
            message=f"Telemetry self-healing recovery completed. Success: {success}"
        )

        if success:
            logger.info("Telemetry self-healing recovery completed successfully.")
        else:
            logger.error("Telemetry self-healing recovery failed to restore OpenSearch connection.")

        return {
            "success": success,
            "opensearch_reconnected": opensearch_reconnected,
            "wazuh_api_reconnected": wazuh_api_reconnected,
            "opensearch_healthy": opensearch_ok,
            "wazuh_api_healthy": wazuh_api_ok
        }
