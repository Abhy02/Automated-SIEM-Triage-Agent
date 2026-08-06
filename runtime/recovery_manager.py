import time
from datetime import datetime
from config import Config
from .logger import log_runtime_event, get_runtime_logger
from .privileged_executor import get_privileged_executor
from .connection_monitor import ConnectionMonitor, ConnectionState
from .wazuh_health import WazuhHealthMonitor

logger = get_runtime_logger()


class RuntimeRecoveryManager:
    """
    Enterprise Runtime Health & Automatic Recovery Manager.
    Orchestrates targeted service recovery, exponential backoff,
    and post-recovery SIEM alert flow validation.
    """

    def __init__(self):
        self.executor = get_privileged_executor()
        self.connection_monitor = ConnectionMonitor()
        self.wazuh_health_monitor = WazuhHealthMonitor()
        self.consecutive_failures = 0
        self.last_recovery_time = 0
        self.backoff_base_delay = 5  # Initial backoff delay in seconds
        self.max_backoff_delay = 120  # Maximum backoff delay in seconds

    def _calculate_backoff_delay(self) -> float:
        delay = min(self.backoff_base_delay * (2 ** self.consecutive_failures), self.max_backoff_delay)
        return delay

    def verify_alert_flow(self) -> bool:
        """
        Verifies that SIEM alerts are flowing from OpenSearch into the platform.
        Checks latest alert timestamp and total count.
        """
        try:
            from services.opensearch_client import get_latest_alerts
            alerts = get_latest_alerts(size=5)
            if alerts:
                logger.info("Alert flow verification passed: Live alerts retrieved from OpenSearch.")
                return True
            elif Config.DEMO_MODE:
                logger.info("Alert flow verification passed (Demo Mode active).")
                return True
        except Exception as e:
            logger.warning(f"Alert flow verification exception: {e}")

        return False

    def execute_targeted_recovery(self, connection_info: dict) -> dict:
        """
        Executes targeted recovery based on detected connection state.
        Never restarts services unnecessarily.
        """
        now = time.time()
        backoff = self._calculate_backoff_delay()
        time_since_last = now - self.last_recovery_time

        if time_since_last < backoff and self.consecutive_failures > 0:
            logger.info(f"Recovery backoff active ({int(backoff - time_since_last)}s remaining). Skipping immediate recovery cycle.")
            return {"success": False, "reason": "Backoff active"}

        self.last_recovery_time = now
        state = connection_info.get("state", ConnectionState.HEALTHY)
        reason = connection_info.get("reason", "Unknown connection failure")
        target_ip = connection_info.get("ip")

        logger.info(f"Initiating targeted recovery sequence. State: {state} | Reason: {reason}")
        log_runtime_event(
            event_type=state,
            connection_lost=True,
            recovery_started=True,
            recovery_successful=False,
            reason=reason
        )

        agent_restarted = False
        manager_restarted = False
        opensearch_status = "Unknown"

        # 1. Handle IP Change or Laptop Sleep Resume
        if state in (ConnectionState.IP_CHANGE, ConnectionState.LAPTOP_SLEEP, ConnectionState.NETWORK_LOST):
            if target_ip:
                from network.config_updater import ConfigurationUpdater
                updater = ConfigurationUpdater()
                updater.apply_ip_update(target_ip)

        # 2. Targeted Agent Restart (Only when agent is disconnected or stopped)
        if state in (ConnectionState.AGENT_DISCONNECTED, ConnectionState.IP_CHANGE, ConnectionState.LAPTOP_SLEEP):
            wazuh_health = self.wazuh_health_monitor.check_wazuh_health()
            if not wazuh_health["agent_process_running"] or state != ConnectionState.HEALTHY:
                logger.info("Agent disconnected or degraded. Executing targeted wazuh-agent restart...")
                agent_restarted = self.executor.restart_service_safe("wazuh-agent")
                time.sleep(3)

        # 3. Targeted Manager Container Restart (Only if manager API unresponsive as last resort)
        if state == ConnectionState.MANAGER_RESTART and self.consecutive_failures >= 2:
            logger.warning("Wazuh Manager API unreachable after retries. Restarting Wazuh Manager Docker container...")
            try:
                from network.wazuh_recovery import WazuhRecoveryManager
                wm = WazuhRecoveryManager()
                containers = wm.restart_wazuh_containers()
                manager_restarted = len(containers) > 0
            except Exception as e:
                logger.error(f"Manager container restart failed: {e}")

        # 4. Verify post-recovery connectivity & alert flow
        post_info = self.connection_monitor.evaluate_connection_state()
        post_healthy = (post_info["state"] == ConnectionState.HEALTHY) or Config.DEMO_MODE
        alert_flow_ok = self.verify_alert_flow() if post_healthy else False

        success = post_healthy or alert_flow_ok

        if success:
            self.consecutive_failures = 0
            opensearch_status = "Online"
            log_runtime_event(
                event_type="RECOVERY_SUCCESS",
                connection_lost=False,
                recovery_started=True,
                recovery_successful=True,
                agent_restarted=agent_restarted,
                manager_restarted=manager_restarted,
                opensearch_status=opensearch_status,
                reason="Recovery completed successfully"
            )
            logger.info("Runtime Recovery Sequence completed successfully.")
        else:
            self.consecutive_failures += 1
            opensearch_status = "Degraded"
            log_runtime_event(
                event_type="RECOVERY_FAILED",
                connection_lost=True,
                recovery_started=True,
                recovery_successful=False,
                agent_restarted=agent_restarted,
                manager_restarted=manager_restarted,
                opensearch_status=opensearch_status,
                reason=f"Recovery verification failed (failure count: {self.consecutive_failures})",
                error=reason
            )
            logger.error("Runtime Recovery Sequence failed post-verification.")

        return {
            "success": success,
            "agent_restarted": agent_restarted,
            "manager_restarted": manager_restarted,
            "consecutive_failures": self.consecutive_failures,
            "post_state": post_info.get("state")
        }
