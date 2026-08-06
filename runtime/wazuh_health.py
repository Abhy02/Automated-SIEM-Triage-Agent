import os
import subprocess
import shutil
from .logger import get_runtime_logger
from .privileged_executor import get_privileged_executor

logger = get_runtime_logger()
CLIENT_KEYS_FILE = "/var/ossec/etc/client.keys"


class WazuhHealthMonitor:
    """
    Wazuh Agent & Manager Detailed Health Inspector.
    Inspects process status, client keys validity, and logcollector telemetry state.
    """

    def __init__(self):
        self.executor = get_privileged_executor()

    def has_valid_client_keys(self) -> bool:
        """Verify client.keys file contains valid enrollment credentials."""
        content = self.executor.read_file_safe(CLIENT_KEYS_FILE)
        if not content:
            return False
        lines = [line.strip() for line in content.strip().splitlines() if line.strip() and not line.strip().startswith("#")]
        return len(lines) > 0

    def is_agent_process_running(self) -> bool:
        """Check if wazuh-agentd or ossec-agentd processes are active."""
        try:
            res = subprocess.run(
                ["pgrep", "-f", "wazuh-agentd|ossec-agentd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            return res.returncode == 0
        except Exception:
            return False

    def is_logcollector_running(self) -> bool:
        """Check if wazuh-logcollector process is active."""
        try:
            res = subprocess.run(
                ["pgrep", "-f", "wazuh-logcollector"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            return res.returncode == 0
        except Exception:
            return False

    def check_wazuh_health(self) -> dict:
        """
        Runs comprehensive Wazuh agent and manager health inspection.
        """
        agent_running = self.is_agent_process_running()
        logcollector_running = self.is_logcollector_running()
        keys_valid = self.has_valid_client_keys()

        is_healthy = agent_running and logcollector_running and keys_valid

        status_str = "Healthy" if is_healthy else "Degraded"
        if not agent_running:
            status_str = "Agent Stopped"
        elif not keys_valid:
            status_str = "Unenrolled / Missing Keys"

        return {
            "healthy": is_healthy,
            "status": status_str,
            "agent_process_running": agent_running,
            "logcollector_running": logcollector_running,
            "client_keys_valid": keys_valid,
        }
