from datetime import datetime
from zoneinfo import ZoneInfo


def format_timestamp(timestamp):
    """
    Convert UTC timestamp from OpenSearch to 24-hour IST (Indian Standard Time).
    Example output: '29 Jul 2026 12:32:40 IST'
    """
    if not timestamp:
        return "-"

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        dt = dt.astimezone(ZoneInfo("Asia/Kolkata"))
        return dt.strftime("%d %b %Y %H:%M:%S IST")
    except Exception:
        return str(timestamp)


def severity_badge(level):
    """
    Convert Wazuh rule level into severity text.
    """
    level = int(level)

    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"

    return "Low"
