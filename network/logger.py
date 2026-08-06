import os
import re
import logging
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
RECOVERY_LOG_FILE = os.path.join(LOGS_DIR, "network_recovery.log")
NETWORK_RUNTIME_LOG_FILE = os.path.join(LOGS_DIR, "network_runtime.log")

_lock = threading.Lock()
_logger_initialized = False
_runtime_logger_initialized = False


def ensure_logs_dir():
    """Ensure the logs directory exists."""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR, exist_ok=True)


class SensitiveDataFilter(logging.Filter):
    """
    Sanitizes secrets, passwords, credentials, and tokens from log messages.
    Ensures passwords and API tokens are never logged to disk or console.
    """
    SENSITIVE_PATTERNS = [
        r"(?:password|pass|secret|token|api[_-]?key|auth)=['\"]?[^'\";\s]+['\"]?",
        r"https?://([^:]+):([^@]+)@",
        r"(?:Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*",
    ]

    def filter(self, record):
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.SENSITIVE_PATTERNS:
                msg = re.sub(pattern, "[REDACTED]", msg, flags=re.IGNORECASE)
            record.msg = msg
        return True


def get_network_logger():
    """
    Returns configured logger writing to logs/network_recovery.log and logs/network_runtime.log.
    """
    global _logger_initialized
    ensure_logs_dir()
    logger = logging.getLogger("NetworkRecovery")

    if not _logger_initialized:
        logger.setLevel(logging.INFO)

        # File Handler for logs/network_recovery.log
        fh = logging.FileHandler(RECOVERY_LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [NetworkRecovery] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        fh.addFilter(SensitiveDataFilter())

        # File Handler for logs/network_runtime.log
        fh_rt = logging.FileHandler(NETWORK_RUNTIME_LOG_FILE, encoding="utf-8")
        fh_rt.setLevel(logging.INFO)
        fh_rt.setFormatter(formatter)
        fh_rt.addFilter(SensitiveDataFilter())

        # Console Stream Handler
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        sh.addFilter(SensitiveDataFilter())

        logger.addHandler(fh)
        logger.addHandler(fh_rt)
        logger.addHandler(sh)
        logger.propagate = False
        _logger_initialized = True

    return logger


def log_recovery_event(
    old_ip=None,
    new_ip=None,
    config_updated=False,
    agent_restarted=False,
    agent_status="Unknown",
    opensearch_status="Unknown",
    dashboard_status="Connected",
    recovery_result="Success",
    error=None
):
    """
    Logs structured recovery event details into network_recovery.log and network_runtime.log.
    """
    logger = get_network_logger()

    details = [
        f"Old IP: {old_ip or 'N/A'}",
        f"New IP: {new_ip or 'N/A'}",
        f"Configuration Updated: {config_updated}",
        f"Agent Restarted: {agent_restarted}",
        f"Agent Status: {agent_status}",
        f"OpenSearch Status: {opensearch_status}",
        f"Dashboard Status: {dashboard_status}",
        f"Recovery Result: {recovery_result}"
    ]

    if error:
        details.append(f"Error: {error}")

    message = " | ".join(details)
    if recovery_result.lower() in ("failed", "error") or error:
        logger.error(message)
    else:
        logger.info(message)
