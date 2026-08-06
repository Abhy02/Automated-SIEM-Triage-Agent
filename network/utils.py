import os
import json
import logging
import re
import threading
from datetime import datetime

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOGS_DIR, "network_manager.log")
STATE_FILE = os.path.join(LOGS_DIR, "network_state.json")

_lock = threading.Lock()
_logger_initialized = False


def _ensure_logs_dir():
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR, exist_ok=True)


class SensitiveDataFilter(logging.Filter):
    """Filter to sanitize secrets/passwords/keys before writing logs."""
    SENSITIVE_PATTERNS = [
        r"(?:password|pass|secret|token|api[_-]?key)=['\"]?[^'\";\s]+['\"]?",
        r"https://[^:]+:([^@]+)@",
    ]

    def filter(self, record):
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.SENSITIVE_PATTERNS:
                msg = re.sub(pattern, "[REDACTED]", msg, flags=re.IGNORECASE)
            record.msg = msg
        return True


def get_network_manager_logger():
    global _logger_initialized
    _ensure_logs_dir()
    logger = logging.getLogger("NetworkManager")
    
    if not _logger_initialized:
        logger.setLevel(logging.INFO)

        # File Handler
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [NetworkManager] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        fh.addFilter(SensitiveDataFilter())

        # Stream Handler
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        sh.addFilter(SensitiveDataFilter())

        logger.addHandler(fh)
        logger.addHandler(sh)
        logger.propagate = False
        _logger_initialized = True

    return logger


def log_network_event(old_ip=None, new_ip=None, config_updated=False, services_restarted=None, health_passed=False, error=None, rollback_status=None):
    logger = get_network_manager_logger()
    
    details = []
    if old_ip or new_ip:
        details.append(f"IP Transition: {old_ip or 'Unknown'} -> {new_ip or 'Unknown'}")
    details.append(f"Configuration Updated: {config_updated}")
    if services_restarted:
        details.append(f"Services Restarted: {', '.join(services_restarted)}")
    details.append(f"Health Check Passed: {health_passed}")
    if rollback_status:
        details.append(f"Rollback Status: {rollback_status}")
    if error:
        details.append(f"Errors: {error}")

    msg = " | ".join(details)
    if error or (rollback_status and "Failed" in str(rollback_status)):
        logger.error(msg)
    else:
        logger.info(msg)


def load_network_state():
    _ensure_logs_dir()
    with _lock:
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        
        default_state = {
            "auto_recovery_enabled": True,
            "last_known_ip": None,
            "last_ip_change": None,
            "last_health_check": None,
            "last_health_status": "Unknown",
            "last_status_message": "Initialized"
        }
        return default_state


def save_network_state(state):
    _ensure_logs_dir()
    with _lock:
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            get_network_manager_logger().error(f"Failed to save network state: {e}")
