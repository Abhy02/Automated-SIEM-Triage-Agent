"""
AI Incident Report Service
--------------------------
Generates an AI-style incident report from a Wazuh alert.

Version 1:
- Rule-based intelligence
- AI Investigation Timeline
- Ready for OpenAI/Ollama integration
"""

from datetime import datetime


class AIReportService:

    MITRE_MAPPING = {
        "5710": {
            "technique": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
        },
        "5503": {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion",
        },
    }

    @staticmethod
    def generate(alert):
        """
        Generate an AI Incident Report from a Wazuh alert.
        """

        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        severity = rule.get("level", 0)
        rule_id = str(rule.get("id", "Unknown"))
        description = rule.get("description", "No description")

        hostname = agent.get("name", "Unknown")

        source_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("ip")
            or "Unknown"
        )

        username = (
            data.get("srcuser")
            or data.get("user")
            or "Unknown"
        )

        mitre = AIReportService.MITRE_MAPPING.get(
            rule_id,
            {
                "technique": "Unknown",
                "name": "Unknown",
                "tactic": "Unknown",
            },
        )

        # --------------------------------------------------
        # Risk Assessment
        # --------------------------------------------------

        if severity >= 12:
            risk = "Critical"
            confidence = 99

        elif severity >= 8:
            risk = "High"
            confidence = 96

        elif severity >= 5:
            risk = "Medium"
            confidence = 90

        else:
            risk = "Low"
            confidence = 82

        # --------------------------------------------------
        # Executive Summary
        # --------------------------------------------------

        summary = (
            f"{description} was detected on endpoint "
            f"'{hostname}'. "
            f"The activity originated from {source_ip}. "
            f"AISOC recommends analyst verification before containment."
        )

        # --------------------------------------------------
        # Recommendations
        # --------------------------------------------------

        recommendations = [
            "Review related authentication logs.",
            "Validate whether the activity is expected.",
            "Block malicious IP addresses if confirmed.",
            "Check for lateral movement or repeated alerts.",
            "Monitor the affected endpoint for additional activity.",
        ]

        # --------------------------------------------------
        # Investigation Timeline
        # --------------------------------------------------

        current_time = datetime.utcnow().strftime("%H:%M:%S")

        timeline = [
            {
                "time": current_time,
                "title": "Alert Received",
                "description": "Wazuh generated a security alert.",
                "status": "info",
            },
            {
                "time": current_time,
                "title": "AI Analysis Started",
                "description": "AISOC parsed the alert metadata and rule information.",
                "status": "processing",
            },
            {
                "time": current_time,
                "title": "IOC Extraction",
                "description": (
                    f"Host: {hostname} | "
                    f"Source IP: {source_ip} | "
                    f"User: {username}"
                ),
                "status": "success",
            },
            {
                "time": current_time,
                "title": "MITRE ATT&CK Mapping",
                "description": (
                    f"{mitre['technique']} - "
                    f"{mitre['name']} "
                    f"({mitre['tactic']})"
                ),
                "status": "success",
            },
            {
                "time": current_time,
                "title": "Risk Assessment Completed",
                "description": (
                    f"Risk classified as {risk} "
                    f"with {confidence}% confidence."
                ),
                "status": "complete",
            },
            {
                "time": current_time,
                "title": "AI Incident Report Generated",
                "description": (
                    "Investigation completed and report "
                    "generated successfully."
                ),
                "status": "complete",
            },
        ]

        # --------------------------------------------------
        # Return Report
        # --------------------------------------------------

        return {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),

            "rule_id": rule_id,

            "severity": severity,

            "risk": risk,

            "summary": summary,

            "description": description,

            "hostname": hostname,

            "source_ip": source_ip,

            "username": username,

            "mitre": mitre,

            "recommendations": recommendations,

            "confidence": confidence,

            "timeline": timeline,
        }
