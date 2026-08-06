import threading
import time
from .logger import get_runtime_logger
from .connection_monitor import ConnectionMonitor, ConnectionState
from .recovery_manager import RuntimeRecoveryManager

logger = get_runtime_logger()

_global_watchdog_instance = None
_global_watchdog_lock = threading.Lock()


class RuntimeWatchdog:
    """
    Enterprise Runtime Watchdog Daemon.
    Monitors platform health continuously in an asynchronous background thread (<1% CPU).
    Triggers targeted automatic recovery without blocking Flask web routes or UI handlers.
    """

    def __init__(self, check_interval: int = 15):
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.connection_monitor = ConnectionMonitor()
        self.recovery_manager = RuntimeRecoveryManager()

    def start(self):
        """Starts the background watchdog daemon thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._watchdog_loop, daemon=True, name="RuntimeWatchdogThread")
        self.thread.start()
        logger.info(f"Runtime Watchdog daemon started (interval: {self.check_interval}s, CPU < 1%).")

    def stop(self):
        """Stops the background watchdog daemon thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("Runtime Watchdog daemon stopped.")

    def _watchdog_loop(self):
        """Background health evaluation loop."""
        while self.running:
            try:
                # Sleep interval keeping CPU usage < 0.1%
                time.sleep(self.check_interval)
                if not self.running:
                    break

                # Evaluate connection and system health state
                conn_info = self.connection_monitor.evaluate_connection_state()
                state = conn_info.get("state", ConnectionState.HEALTHY)

                if state != ConnectionState.HEALTHY:
                    logger.warning(f"Watchdog detected unhealthy state: {state} | Reason: {conn_info.get('reason')}")
                    # Trigger targeted non-blocking recovery
                    self.recovery_manager.execute_targeted_recovery(conn_info)

            except Exception as e:
                logger.error(f"Unexpected exception in RuntimeWatchdog loop: {e}")


def get_runtime_watchdog() -> RuntimeWatchdog:
    global _global_watchdog_instance
    with _global_watchdog_lock:
        if _global_watchdog_instance is None:
            _global_watchdog_instance = RuntimeWatchdog()
        return _global_watchdog_instance


def start_runtime_watchdog() -> RuntimeWatchdog:
    watchdog = get_runtime_watchdog()
    watchdog.start()
    return watchdog
