import time
from datetime import datetime
from .logger import get_network_logger, log_recovery_event
from .ip_detector import get_active_lan_ip
from .config_updater import ConfigurationUpdater
from .wazuh_recovery import WazuhRecoveryManager
from .health_checker import HealthChecker
from .utils import load_network_state, save_network_state

logger = get_network_logger()


class RecoveryManager:
    """
    Enterprise Network Auto-Recovery Engine.
    Orchestrates network change detection, configuration backups & updates,
    service recovery, health verification, and automatic alert stream recovery.
    """

    def __init__(self):
        self.config_updater = ConfigurationUpdater()
        self.wazuh_recovery = WazuhRecoveryManager()
        self.health_checker = HealthChecker()
        self.alert_recovery_attempts = 0

    def verify_alert_stream(self, current_ip: str) -> bool:
        """
        Verify that new alerts are actively arriving from Wazuh / OpenSearch.
        If alert stream has stopped, attempts 1 automatic recovery retry of Wazuh agent.
        """
        logger.info("Verifying active SIEM alert stream post-network recovery...")
        health = self.health_checker.perform_full_health_check(current_ip)
        
        if health.get("overall_healthy"):
            self.alert_recovery_attempts = 0
            logger.info("Alert stream verification passed successfully.")
            return True

        if self.alert_recovery_attempts < 1:
            self.alert_recovery_attempts += 1
            logger.warning(
                f"SIEM Alert stream degraded or disconnected. "
                f"Attempting automatic recovery retry #{self.alert_recovery_attempts}..."
            )
            restarted = self.wazuh_recovery.restart_required_services()
            time.sleep(3)
            post_retry_health = self.health_checker.perform_full_health_check(current_ip)
            
            if post_retry_health.get("overall_healthy"):
                logger.info("Alert stream successfully recovered on retry attempt.")
                return True
            else:
                logger.error("Alert stream automatic recovery retry failed.")
                return False

        return False

    def execute_network_recovery(self, force_update: bool = False) -> dict:
        """
        Executes complete network recovery sequence:
        1. Detect Current Active LAN IPv4
        2. Backup .env and ossec.conf (.env.bak & ossec.conf.bak)
        3. Update configuration files & runtime memory
        4. Reconnect & restart required services
        5. Perform full health verification
        6. Verify alert stream & handle recovery
        7. Log event details into logs/network_recovery.log
        """
        state = load_network_state()
        last_ip = state.get("last_known_ip")
        current_ip = get_active_lan_ip()

        if not current_ip:
            logger.warning("No active physical LAN IPv4 interface detected.")
            log_recovery_event(
                old_ip=last_ip,
                new_ip=None,
                config_updated=False,
                agent_restarted=False,
                agent_status="Disconnected",
                opensearch_status="Offline",
                dashboard_status="Offline",
                recovery_result="Failed",
                error="No LAN IPv4 address detected"
            )
            return {
                "success": False,
                "reason": "No LAN IPv4 address detected",
                "old_ip": last_ip,
                "new_ip": None,
            }

        ip_changed = (current_ip != last_ip)
        if not ip_changed and not force_update:
            logger.debug(f"LAN IP unchanged ({current_ip}). No recovery required.")
            return {
                "success": True,
                "ip_changed": False,
                "current_ip": current_ip,
            }

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Network Change Event Detected! [Transition: {last_ip} -> {current_ip}]")

        # 1. Apply configuration updates with backup safety (.env.bak & ossec.conf.bak)
        config_ok = self.config_updater.apply_ip_update(current_ip)
        if not config_ok:
            log_recovery_event(
                old_ip=last_ip,
                new_ip=current_ip,
                config_updated=False,
                agent_restarted=False,
                agent_status="Unknown",
                opensearch_status="Unknown",
                dashboard_status="Degraded",
                recovery_result="Failed",
                error="Configuration update failed"
            )
            return {
                "success": False,
                "reason": "Configuration update failed",
                "old_ip": last_ip,
                "new_ip": current_ip,
            }

        # 2. Reconnect / restart required services intelligently
        restarted_services = self.wazuh_recovery.restart_required_services()
        agent_restarted = "wazuh-agent" in restarted_services

        # 3. Perform automatic health check
        health_report = self.health_checker.perform_full_health_check(current_ip)
        is_healthy = health_report.get("overall_healthy", False)
        agent_status = health_report.get("wazuh_agent", {}).get("status", "unknown")
        opensearch_status = health_report.get("opensearch", {}).get("status", "unknown")

        # 4. Verify alert arrival flow
        alert_flow_ok = self.verify_alert_stream(current_ip) if is_healthy else False

        if not is_healthy and not alert_flow_ok:
            logger.error("Health check failed post-recovery. Initiating rollback...")
            rollback_ok = self.config_updater.rollback()
            log_recovery_event(
                old_ip=last_ip,
                new_ip=current_ip,
                config_updated=True,
                agent_restarted=agent_restarted,
                agent_status=agent_status,
                opensearch_status=opensearch_status,
                dashboard_status="Rolled back",
                recovery_result="Rolled back",
                error="Health verification failed post IP update"
            )
            return {
                "success": False,
                "reason": "Health verification failed; rolled back",
                "old_ip": last_ip,
                "new_ip": current_ip,
            }

        # 5. Persist state on success
        state["last_known_ip"] = current_ip
        state["last_ip_change"] = now_str
        state["last_health_check"] = now_str
        state["last_health_status"] = "Healthy" if is_healthy else "Degraded"
        save_network_state(state)

        log_recovery_event(
            old_ip=last_ip,
            new_ip=current_ip,
            config_updated=True,
            agent_restarted=agent_restarted,
            agent_status=agent_status,
            opensearch_status=opensearch_status,
            dashboard_status="Connected",
            recovery_result="Success",
            error=None
        )

        logger.info(f"Network Recovery Sequence completed successfully for IP: {current_ip}")

        return {
            "success": True,
            "ip_changed": True,
            "old_ip": last_ip,
            "new_ip": current_ip,
            "restarted_services": restarted_services,
            "health": health_report,
        }
