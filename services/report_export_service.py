import json
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


def save_incident_report(report_data: dict) -> str:
    """
    Save generated AI Incident Report to disk as JSON.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rule_id = report_data.get("rule_id", "incident")
    filename = f"report_rule_{rule_id}_{timestamp_str}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    return filepath


def list_saved_reports() -> list:
    """
    List all exported incident reports stored in the reports directory.
    """
    if not os.path.exists(REPORTS_DIR):
        return []

    reports = []
    for fn in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if fn.endswith(".json"):
            fp = os.path.join(REPORTS_DIR, fn)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    reports.append({
                        "filename": fn,
                        "filepath": fp,
                        "created_at": content.get("generated_at", "N/A"),
                        "rule_id": content.get("rule_id", "N/A"),
                        "severity": content.get("severity", 0),
                        "risk": content.get("risk", "Low"),
                        "summary": content.get("summary", "")
                    })
            except Exception:
                continue

    return reports
