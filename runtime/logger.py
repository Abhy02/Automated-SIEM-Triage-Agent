import os
import re
import logging
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
RUNTIME_LOG_FILE = os.path.join(LOGS_DIR, "runtime_health.log")

_lock = threading.Lock()
_logger_initialized = False


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


def get_runtime_logger():
    """
    Returns configured logger writing to logs/runtime_health.log.
    """
    global _logger_initialized
    ensure_logs_dir()
    logger = logging.getLogger("RuntimeHealth")

    if not _logger_initialized:
        logger.setLevel(logging.INFO)

        # File Handler for logs/runtime_health.log
        fh = logging.FileHandler(RUNTIME_LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [RuntimeHealth] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        fh.addFilter(SensitiveDataFilter())

        # Console Stream Handler
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        sh.addFilter(SensitiveDataFilter())

        logger.addHandler(fh)
        logger.addHandler(sh)
        logger.propagate = False
        _logger_initialized = True

    return logger


def log_runtime_event(
    event_type="HEALTH_CHECK",
    connection_lost=False,
    recovery_started=False,
    recovery_successful=False,
    agent_restarted=False,
    manager_restarted=False,
    opensearch_status="Unknown",
    reason=None,
    error=None
):
    """
    Logs structured runtime health and connection recovery details to logs/runtime_health.log.
    """
    logger = get_runtime_logger()

    details = [
        f"Event: {event_type}",
        f"Connection Lost: {connection_lost}",
        f"Recovery Started: {recovery_started}",
        f"Recovery Successful: {recovery_successful}",
        f"Agent Restart: {agent_restarted}",
        f"Manager Restart: {manager_restarted}",
        f"OpenSearch Status: {opensearch_status}",
        f"Reason: {reason or 'Routine Health Check'}"
    ]

    if error:
        details.append(f"Error: {error}")

    message = " | ".join(details)
    if recovery_started and not recovery_successful or error:
        logger.error(message)
    elif recovery_started or connection_lost:
        logger.warning(message)
    else:
        logger.info(message)
