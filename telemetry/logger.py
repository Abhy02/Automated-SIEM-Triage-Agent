import os
import re
import logging
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
TELEMETRY_LOG_FILE = os.path.join(LOGS_DIR, "telemetry_sync.log")

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


def get_telemetry_logger():
    """
    Returns configured logger writing to logs/telemetry_sync.log.
    """
    global _logger_initialized
    ensure_logs_dir()
    logger = logging.getLogger("TelemetrySync")

    if not _logger_initialized:
        logger.setLevel(logging.INFO)

        # File Handler for logs/telemetry_sync.log
        fh = logging.FileHandler(TELEMETRY_LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [TelemetrySync] %(message)s",
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


def log_telemetry_event(
    event_type="SYNC_CHECK",
    opensearch_connected=True,
    wazuh_api_connected=True,
    latest_timestamp=None,
    latest_doc_id=None,
    new_alerts_found=False,
    cache_invalidated=False,
    recovery_triggered=False,
    recovery_successful=False,
    message=None
):
    """
    Logs structured telemetry synchronization details to logs/telemetry_sync.log.
    """
    logger = get_telemetry_logger()

    details = [
        f"Event: {event_type}",
        f"OpenSearch Connected: {opensearch_connected}",
        f"Wazuh API Connected: {wazuh_api_connected}",
        f"Latest Timestamp: {latest_timestamp or 'N/A'}",
        f"New Alerts Found: {new_alerts_found}",
        f"Cache Invalidated: {cache_invalidated}",
        f"Recovery Triggered: {recovery_triggered}",
        f"Recovery Successful: {recovery_successful}",
        f"Message: {message or 'Routine Telemetry Sync'}"
    ]

    log_msg = " | ".join(details)
    if recovery_triggered and not recovery_successful:
        logger.error(log_msg)
    elif new_alerts_found or cache_invalidated or recovery_triggered:
        logger.warning(log_msg)
    else:
        logger.info(log_msg)
