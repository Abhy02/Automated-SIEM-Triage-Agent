import time
import socket
import urllib.request
import urllib.parse
import ssl
import subprocess
from datetime import datetime
from config import Config
from network.ip_detector import get_active_lan_ip, get_active_network_details
from .logger import get_runtime_logger

logger = get_runtime_logger()


class ConnectionState:
    HEALTHY = "HEALTHY"
    NETWORK_LOST = "NETWORK_LOST"
    LAPTOP_SLEEP = "LAPTOP_SLEEP"
    IP_CHANGE = "IP_CHANGE"
    MANAGER_RESTART = "MANAGER_RESTART"
    INDEXER_RESTART = "INDEXER_RESTART"
    AUTH_FAILURE = "AUTH_FAILURE"
    ENROLLMENT_FAILURE = "ENROLLMENT_FAILURE"
    PACKET_LOSS = "PACKET_LOSS"
    AGENT_DISCONNECTED = "AGENT_DISCONNECTED"


class ConnectionMonitor:
    """
    Continuous Connection & System State Evaluation Engine.
    Monitors platform connectivity and classifies connection state root causes.
    """

    def __init__(self):
        self.last_known_ip = None
        self.last_check_timestamp = time.time()

    def _create_unverified_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def is_opensearch_online(self, ip: str = None) -> bool:
        """Verify OpenSearch HTTP 9200 reachability."""
        urls = ["https://127.0.0.1:9200", "http://127.0.0.1:9200"]
        if ip and ip != "127.0.0.1":
            urls.append(f"https://{ip}:9200")
        if Config.OPENSEARCH_HOST and Config.OPENSEARCH_HOST not in urls:
            urls.append(Config.OPENSEARCH_HOST)

        ctx = self._create_unverified_context()
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-RuntimeMonitor"})
                with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                    if resp.status in (200, 401, 403):
                        return True
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    return True
            except Exception:
                pass

        try:
            with socket.create_connection(("127.0.0.1", 9200), timeout=2):
                return True
        except Exception:
            pass

        return False

    def is_wazuh_api_online(self, ip: str = None) -> bool:
        """Verify Wazuh API HTTPS 55000 reachability."""
        urls = ["https://127.0.0.1:55000", "http://127.0.0.1:55000"]
        if ip and ip != "127.0.0.1":
            urls.append(f"https://{ip}:55000")
        if Config.WAZUH_HOST and Config.WAZUH_HOST not in urls:
            urls.append(Config.WAZUH_HOST)

        ctx = self._create_unverified_context()
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-RuntimeMonitor"})
                with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                    return True
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    return True
            except Exception:
                pass

        try:
            with socket.create_connection(("127.0.0.1", 55000), timeout=2):
                return True
        except Exception:
            pass

        return False

    def is_wazuh_agent_active(self) -> bool:
        """Verify wazuh-agent process / service state."""
        try:
            res = subprocess.run(
                ["pgrep", "-f", "wazuh-agentd|ossec-agentd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass
        return False

    def evaluate_connection_state(self) -> dict:
        current_time = time.time()
        time_elapsed = current_time - self.last_check_timestamp
        self.last_check_timestamp = current_time

        current_ip = "127.0.0.1"

        # 1. Detect Laptop Resume / Wake-up (large gap between checks)
        if time_elapsed > 45:
            logger.info(f"System wake-up / resume detected (idle duration: {int(time_elapsed)}s).")
            return {
                "state": ConnectionState.LAPTOP_SLEEP,
                "reason": f"Laptop resumed from sleep (gap: {int(time_elapsed)}s)",
                "ip": current_ip
            }

        # 2. Detect Component Reachability on Localhost
        opensearch_ok = self.is_opensearch_online(current_ip)
        wazuh_api_ok = self.is_wazuh_api_online(current_ip)
        agent_active = self.is_wazuh_agent_active()

        if not opensearch_ok and not Config.DEMO_MODE:
            return {
                "state": ConnectionState.INDEXER_RESTART,
                "reason": "OpenSearch indexer on port 9200 is unreachable on localhost",
                "ip": current_ip
            }

        if not wazuh_api_ok and not Config.DEMO_MODE:
            return {
                "state": ConnectionState.MANAGER_RESTART,
                "reason": "Wazuh Manager API on port 55000 is unreachable on localhost",
                "ip": current_ip
            }

        if not agent_active:
            return {
                "state": ConnectionState.AGENT_DISCONNECTED,
                "reason": "wazuh-agent process is not running",
                "ip": current_ip
            }

        return {
            "state": ConnectionState.HEALTHY,
            "reason": "All platform components and SIEM connections active on 127.0.0.1",
            "ip": current_ip
        }
