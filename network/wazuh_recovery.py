import os
import shutil
import subprocess
import time
from .logger import get_network_logger

logger = get_network_logger()
CLIENT_KEYS_FILE = "/var/ossec/etc/client.keys"


class WazuhRecoveryManager:
    """
    Automatic Wazuh Agent & Service Recovery Engine.
    Handles wazuh-agent status checks, systemctl service restarts,
    safe client key validation, and automatic reconnection retries.
    """

    def is_wazuh_agent_installed(self) -> bool:
        """Check if wazuh-agent system service exists on the host."""
        systemctl_path = shutil.which("systemctl")
        if not systemctl_path:
            return False
        try:
            res = subprocess.run(
                ["systemctl", "status", "wazuh-agent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            # returncode 0 = active, 3 = inactive, 4 = unit not found
            return res.returncode in (0, 3)
        except Exception:
            return False

    def get_agent_status(self) -> str:
        """
        Determines current wazuh-agent service/process state.
        Returns 'active', 'disconnected', 'inactive', or 'not_installed'.
        """
        if not self.is_wazuh_agent_installed():
            # Check if process is running via pgrep as fallback
            try:
                res = subprocess.run(
                    ["pgrep", "-f", "wazuh-agentd|ossec-agentd"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    return "active"
            except Exception:
                pass
            return "not_installed"

        try:
            res = subprocess.run(
                ["systemctl", "is-active", "wazuh-agent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            status = res.stdout.strip()
            if status == "active":
                return "active"
            elif status == "inactive":
                return "inactive"
            else:
                return status or "disconnected"
        except Exception as e:
            logger.debug(f"Error checking wazuh-agent systemctl status: {e}")
            return "unknown"

    def has_valid_client_keys(self) -> bool:
        """
        Checks if /var/ossec/etc/client.keys exists and contains valid enrollment credentials.
        Never overwrites valid client keys.
        """
        if not os.path.exists(CLIENT_KEYS_FILE):
            return False
        try:
            with open(CLIENT_KEYS_FILE, "r") as f:
                content = f.read().strip()
                # client.keys lines format: ID Name IP Key
                return len(content) > 0 and not content.startswith("#")
        except Exception as e:
            logger.debug(f"Error reading client.keys: {e}")
            return False

    def restart_wazuh_agent(self) -> bool:
        """
        Restarts wazuh-agent system service via PrivilegedExecutor (non-interactive sudo & docker fallbacks).
        """
        if not self.is_wazuh_agent_installed():
            logger.info("wazuh-agent system service not installed. Skipping service restart.")
            return False

        from runtime.privileged_executor import get_privileged_executor
        executor = get_privileged_executor()
        return executor.restart_service_safe("wazuh-agent")

    def recover_agent_connection(self, max_retries: int = 2) -> bool:
        """
        Verifies wazuh-agent status and retries reconnection if agent is disconnected.
        Does NOT duplicate agents or overwrite valid client keys.
        """
        status = self.get_agent_status()
        if status == "active":
            logger.info("Wazuh agent is active and connected.")
            return True

        logger.warning(f"Wazuh agent status is '{status}'. Initiating automatic recovery connection retries...")
        
        for attempt in range(1, max_retries + 1):
            logger.info(f"Wazuh Agent Reconnection Retry attempt #{attempt}/{max_retries}...")
            restarted = self.restart_wazuh_agent()
            if restarted:
                time.sleep(3)
                new_status = self.get_agent_status()
                if new_status == "active":
                    logger.info("Wazuh agent reconnected successfully.")
                    return True

        # Check if enrollment key check is needed without overwriting
        if not self.has_valid_client_keys():
            logger.info("Wazuh client.keys empty or unreadable. Automatic enrollment skipped to avoid duplicate agent creation.")

        logger.warning("Wazuh agent recovery attempted but status remains disconnected.")
        return False

    def get_wazuh_docker_containers(self) -> list:
        """Detect running Wazuh or OpenSearch docker containers."""
        docker_path = shutil.which("docker")
        if not docker_path:
            return []

        try:
            res = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                container_names = res.stdout.strip().splitlines()
                return [
                    c for c in container_names 
                    if any(term in c.lower() for term in ("wazuh", "opensearch", "indexer", "manager"))
                ]
        except Exception as e:
            logger.debug(f"Docker ps check exception: {e}")
        return []

    def restart_wazuh_containers(self) -> list:
        """Restart active Wazuh/OpenSearch docker containers."""
        containers = self.get_wazuh_docker_containers()
        restarted = []
        for container in containers:
            logger.info(f"Restarting Docker container: {container}")
            try:
                res = subprocess.run(
                    ["docker", "restart", container],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                if res.returncode == 0:
                    logger.info(f"Successfully restarted container: {container}")
                    restarted.append(container)
            except Exception as e:
                logger.error(f"Error restarting container {container}: {e}")
        return restarted

    def restart_required_services(self) -> list:
        """Intelligently restarts only required active services."""
        restarted = []
        if self.restart_wazuh_agent():
            restarted.append("wazuh-agent")
        docker_restarted = self.restart_wazuh_containers()
        restarted.extend(docker_restarted)
        return restarted


# Alias for backward compatibility
WazuhManager = WazuhRecoveryManager
