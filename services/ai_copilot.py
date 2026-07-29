import json
import logging
import requests

logger = logging.getLogger(__name__)


class AICopilot:
    OLLAMA_URL = "http://localhost:11434/api/generate"
    MODEL = "llama3.2:3b"

    @classmethod
    def ask(cls, prompt: str, alert_context: dict = None) -> str:
        """
        Send contextual analyst query to local Ollama LLM.
        Injects evidence context into prompt for accurate, non-hallucinated answers.
        """
        context_str = ""
        if alert_context:
            context_str = f"ALERT TELEMETRY CONTEXT:\n{json.dumps(alert_context, indent=2)}\n"

        full_prompt = f"""You are a Tier-3 SOC Analyst.
{context_str}
MANDATORY: Answer the analyst query ONLY using the provided evidence context above. If data is missing, state 'Insufficient evidence'.

ANALYST QUERY: {prompt}"""

        payload = {
            "model": cls.MODEL,
            "prompt": full_prompt,
            "stream": False
        }

        try:
            response = requests.post(cls.OLLAMA_URL, json=payload, timeout=20)
            response.raise_for_status()
            return response.json().get("response", "No response generated.")
        except Exception as e:
            logger.warning("Copilot LLM query failed: %s. Generating rule template.", str(e))
            return cls._rule_generator_fallback(prompt, alert_context)

    @classmethod
    def _rule_generator_fallback(cls, prompt: str, alert_context: dict = None) -> str:
        p = prompt.lower()
        rule_id = alert_context.get("rule_id", "5710") if alert_context else "5710"
        desc = alert_context.get("description", "Security Event") if alert_context else "Security Event"

        if "sigma" in p:
            return f"""```yaml
title: Detection Rule - {desc}
id: 9b2d8f1e-4c3a-4b01-8e92-aisoc2026
status: test
description: Detects {desc} (Mapped from Wazuh Rule #{rule_id})
author: AISOC Enterprise Copilot
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        EventID: {rule_id}
    condition: selection
level: high
```"""
        elif "yara" in p:
            return f"""```yara
rule AISOC_Detection_{rule_id} {{
    meta:
        description = "YARA rule generated for {desc}"
        author = "AISOC Enterprise Copilot"
        date = "2026-07-29"
    strings:
        $s1 = "netstat listening ports" ascii
        $s2 = "ossec: output" ascii
    condition:
        any of ($s*)
}}
```"""
        elif "splunk" in p:
            return f'```spl\nindex=security sourcetype="wazuh:alerts" rule.id="{rule_id}" | stats count by agent.name, rule.description\n```'
        elif "kql" in p:
            return f'```kql\nSecurityEvent\n| where EventID == {rule_id}\n| summarize count() by Computer, Account\n```'
        elif "wazuh" in p:
            return f"""```xml
<group name="syslog,errors,">
  <rule id="100570" level="10">
    <if_sid>{rule_id}</if_sid>
    <description>AISOC Custom Rule: {desc}</description>
  </rule>
</group>
```"""
        else:
            return f"""### Triage & Investigation Advice (Rule #{rule_id}):
- **Linux Forensics**: Check system logs via `journalctl -u ssh -n 50 --no-pager` and inspect listening ports using `ss -tulpn`.
- **PowerShell Forensics**: Query failed logons via `Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625}}`.
- **Telemetry Baseline**: Review raw log payload '{desc}' for unexpected binary paths.
"""
