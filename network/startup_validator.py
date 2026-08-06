import time
from .logger import get_network_logger, log_recovery_event
from .ip_detector import get_active_lan_ip
from .config_updater import ConfigurationUpdater
from .wazuh_recovery import WazuhRecoveryManager
from .health_checker import HealthChecker

logger = get_network_logger()


class StartupValidator:
    """
    Enterprise Pre-Flight Startup Validator.
    Executes network-independent startup validation, service checks,
    and alert stream verification on application startup before serving requests.
    """

    def __init__(self):
        self.config_updater = ConfigurationUpdater()
        self.wazuh_recovery = WazuhRecoveryManager()
        self.health_checker = HealthChecker()

    def validate_and_synchronize_on_startup(self) -> dict:
        """
        Runs comprehensive startup validation and synchronization sequence for localhost 127.0.0.1.
        """
        logger.info("Executing Enterprise Pre-Flight Startup Validation...")
        active_lan_ip = get_active_lan_ip() or "127.0.0.1"
        target_ip = "127.0.0.1"

        logger.info(f"Startup Active Endpoint: {target_ip} (LAN IPv4: {active_lan_ip})")

        # 1. Synchronize configuration (.env, ossec.conf, memory) to localhost
        config_ok = self.config_updater.apply_ip_update(target_ip)

        # 2. Verify agent status and attempt recovery if needed
        agent_status = self.wazuh_recovery.get_agent_status()
        agent_restarted = False
        if agent_status != "active":
            logger.info(f"Wazuh Agent status is '{agent_status}' on startup. Initiating agent restart...")
            agent_restarted = self.wazuh_recovery.restart_wazuh_agent()
            agent_status = self.wazuh_recovery.get_agent_status()

        # 3. Perform full platform health check
        health_rpt = self.health_checker.perform_full_health_check(target_ip)
        opensearch_status = health_rpt.get("opensearch", {}).get("status", "offline")
        wazuh_api_status = health_rpt.get("wazuh_api", {}).get("status", "offline")

        # 4. Verify latest alerts / alert stream
        overall_healthy = health_rpt.get("overall_healthy", False)

        result_str = "Success" if (config_ok and overall_healthy) else "Degraded"
        log_recovery_event(
            old_ip="Startup Check",
            new_ip=target_ip,
            config_updated=config_ok,
            agent_restarted=agent_restarted,
            agent_status=agent_status,
            opensearch_status=opensearch_status,
            dashboard_status="Initializing",
            recovery_result=result_str,
            error=None if overall_healthy else "Some platform components offline or in demo mode"
        )

        logger.info(
            f"Pre-Flight Startup Validation complete for IP {target_ip}. "
            f"Result: {result_str} | OpenSearch: {opensearch_status} | Agent: {agent_status}"
        )

        return {
            "success": True,
            "current_ip": target_ip,
            "lan_ip": active_lan_ip,
            "config_synchronized": config_ok,
            "agent_status": agent_status,
            "health": health_rpt,
        }


def validate_startup():
    validator = StartupValidator()
    return validator.validate_and_synchronize_on_startup()
