import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from parser.ioc_extractor import extract_iocs
from parser.risk_engine import calculate_risk
from threat_intel.intel_engine import enrich_iocs

console = Console()
ALERT_FILE = Path("sample_alerts/alerts.json")


def load_last_alert():
    with ALERT_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        raise RuntimeError("alerts.json is empty")
    return json.loads(lines[-1])


def display(alert, risk, iocs, intel, mitre, report):
    table = Table(title="Latest Wazuh Alert")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Timestamp", alert.timestamp or "")
    table.add_row("Rule ID", str(alert.rule_id or ""))
    table.add_row("Severity", str(alert.severity or ""))
    table.add_row("Risk Score", risk)
    table.add_row("Description", alert.description or "")
    table.add_row("Agent", alert.agent_name or "")
    table.add_row("Agent IP", alert.agent_ip or "")
    table.add_row("Location", getattr(alert, "location", "") or "")

    mitre_attr = getattr(alert, "mitre_techniques", None)
    if mitre_attr:
        table.add_row("MITRE", ", ".join(mitre_attr))

    console.print(table)

    ioc_table = Table(title="Extracted IOCs")
    ioc_table.add_column("Type", style="cyan")
    ioc_table.add_column("Value", style="green")
    for ip in iocs["ips"]:
        ioc_table.add_row(ip["type"], ip["ip"])
    for domain in iocs["domains"]:
        ioc_table.add_row("Domain", domain)
    for url in iocs["urls"]:
        ioc_table.add_row("URL", url)
    for h in iocs["hashes"]:
        ioc_table.add_row("Hash", h)
    console.print(ioc_table)

    if intel:
        vt_table = Table(title="Threat Intelligence")

        vt_table.add_column("IP")
        vt_table.add_column("Malicious")
        vt_table.add_column("Suspicious")
        vt_table.add_column("Harmless")

        for item in intel:
            vt = item["virustotal"]

            if "error" in vt:
                vt_table.add_row(
                    item["ip"],
                    "Error",
                    "-",
                    "-"
                )
            else:
                vt_table.add_row(
                    item["ip"],
                    str(vt["malicious"]),
                    str(vt["suspicious"]),
                    str(vt["harmless"])
                )

        console.print(vt_table)

    # MITRE ATT&CK table
    if mitre:
        mitre_table = Table(title="MITRE ATT&CK")
        mitre_table.add_column("Field")
        mitre_table.add_column("Value")

        mitre_table.add_row("Technique", mitre.get("technique", ""))
        mitre_table.add_row("Name", mitre.get("name", ""))
        mitre_table.add_row("Tactic", mitre.get("tactic", ""))

        console.print(mitre_table)

    # AI Incident Report
    if report:
        analysis = (
            f"[bold]Summary[/bold]\n"
            f"{report.get('summary', '')}\n\n"
            f"[bold]Observations[/bold]\n"
        )

        for obs in report.get("observations", []):
            analysis += f"• {obs}\n"

        analysis += "\n[bold]Recommendations[/bold]\n"

        for rec in report.get("recommendations", []):
            analysis += f"• {rec}\n"

        console.print(
            Panel(
                analysis,
                title="AI Incident Report",
                expand=False,
            )
        )


if __name__ == "__main__":
    alert = load_last_alert()
    display(alert)
