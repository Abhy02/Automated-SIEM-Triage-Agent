import threading
import time
from datetime import datetime

from .logger import get_network_logger, log_recovery_event
from .ip_detector import get_active_lan_ip, get_active_network_details
from .config_updater import ConfigurationUpdater
from .wazuh_recovery import WazuhRecoveryManager
from .health_checker import HealthChecker
from .recovery_manager import RecoveryManager
from .utils import load_network_state, save_network_state

logger = get_network_logger()

_global_monitor_instance = None
_global_monitor_lock = threading.Lock()


class NetworkMonitor:
    """
    Enterprise Network Event & Change Monitoring Daemon.
    Uses event-driven signals, DBus / NetworkManager event triggers,
    and a lightweight background loop (<1% CPU) for automatic network recovery.
    """

    def __init__(self, check_interval=10):
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.state = load_network_state()
        self.config_updater = ConfigurationUpdater()
        self.wazuh_recovery = WazuhRecoveryManager()
        self.health_checker = HealthChecker()
        self.recovery_manager = RecoveryManager()

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="NetworkMonitorThread")
        self.thread.start()
        logger.info(f"NetworkMonitor event daemon started (idle check: {self.check_interval}s).")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("NetworkMonitor daemon stopped.")

    def set_auto_recovery(self, enabled: bool):
        self.state["auto_recovery_enabled"] = bool(enabled)
        save_network_state(self.state)
        logger.info(f"Auto Network Recovery setting updated: {self.state['auto_recovery_enabled']}")
        return self.state["auto_recovery_enabled"]

    def get_status(self):
        net_details = get_active_network_details()
        current_ip = net_details["ip"]
        health_rpt = self.health_checker.perform_full_health_check(current_ip if current_ip != "Disconnected" else None)
        
        return {
            "current_ip": current_ip,
            "network_interface": net_details["interface"],
            "current_gateway": net_details["gateway"],
            "network_name": net_details["network_name"],
            "auto_recovery_enabled": self.state.get("auto_recovery_enabled", True),
            "last_known_ip": self.state.get("last_known_ip"),
            "last_ip_change": self.state.get("last_ip_change", "Initial / Never"),
            "last_health_check": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_health_status": "Healthy" if health_rpt["overall_healthy"] else "Degraded",
            "details": health_rpt
        }

    def trigger_rescan_and_recovery(self, force=False):
        """
        Executes immediate network rescan, configuration update, service restart, and health check.
        Called on manual rescan request or system resume / NetworkManager dispatcher event.
        """
        logger.info("Executing immediate IP rescan & network recovery sequence...")
        res = self.recovery_manager.execute_network_recovery(force_update=force)
        return res.get("success", False)

    def _process_ip_check(self, force_update=False):
        current_ip = get_active_lan_ip()
        if not current_ip:
            logger.debug("No active LAN IP address detected.")
            return False

        last_ip = self.state.get("last_known_ip")
        
        if current_ip != last_ip or force_update:
            if not self.state.get("auto_recovery_enabled", True) and not force_update:
                logger.warning("Auto Network Recovery is DISABLED. Skipping configuration update.")
                self.state["last_known_ip"] = current_ip
                save_network_state(self.state)
                return False

            res = self.recovery_manager.execute_network_recovery(force_update=force_update)
            return res.get("success", False)
        else:
            if not self.state.get("last_known_ip"):
                self.state["last_known_ip"] = current_ip
                save_network_state(self.state)

        return False

    def _monitor_loop(self):
        # Initial check on daemon start
        try:
            self._process_ip_check()
        except Exception as e:
            logger.error(f"Error during initial network monitor check: {e}")

        while self.running:
            try:
                # Sleep interval keeping CPU usage < 0.1%
                time.sleep(self.check_interval)
                if self.running:
                    self._process_ip_check()
            except Exception as e:
                logger.error(f"Unexpected error in NetworkMonitor loop: {e}")


def get_network_monitor():
    global _global_monitor_instance
    with _global_monitor_lock:
        if _global_monitor_instance is None:
            _global_monitor_instance = NetworkMonitor()
        return _global_monitor_instance


def start_network_monitor():
    monitor = get_network_monitor()
    monitor.start()
    return monitor
