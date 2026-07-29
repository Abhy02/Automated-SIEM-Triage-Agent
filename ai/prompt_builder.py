import json


class PromptBuilder:

    @staticmethod
    def build(context: dict) -> str:
        """
        Build an evidence-first prompt for Ollama using the structured investigation context.
        Instructs the model to act as a Tier-3 SOC Analyst reasoning ONLY from provided evidence.
        """
        context_json = json.dumps(context, indent=2)

        return f"""
You are a Senior Tier-3 SOC Architect and Lead Malware Analyst investigating a security incident.

EVIDENCE TELEMETRY CONTEXT:
{context_json}

MANDATORY INSTRUCTIONS:
1. Reason ONLY from the evidence supplied in the context above.
2. NEVER guess, assume, or hallucinate information. If data is unavailable, state "Insufficient evidence."
3. Every conclusion and recommendation must be directly grounded in the raw log, decoder fields, or telemetry.
4. Two different Wazuh alerts must NEVER produce generic boilerplate reports. Produce alert-category-specific analysis.
5. If public Threat Intel shows no malicious flags, explain: "No external intelligence indicates malicious activity."

RETURN ONLY A VALID JSON OBJECT MATCHING THIS EXACT SCHEMA (no markdown outside JSON):
{{
    "summary": "Executive summary under 4 sentences answering: What happened, Why it matters, Current risk, Immediate action.",
    "root_cause": "Specific technical explanation of why the alert triggered based on raw log evidence.",
    "classification": "Benign / Administrative Activity / Configuration Change / Credential Attack / Reconnaissance / Malware / Unknown",
    "confidence": "High / Medium / Low (with percentage e.g. 92% based on evidence availability)",
    "business_impact": "Impact on host availability, data confidentiality, or security compliance.",
    "affected_assets": "Impacted endpoint names, IPs, or services.",
    "timeline": ["12:30 - Description of evidence step 1", "12:32 - Description of evidence step 2"],
    "mitre": {{
        "technique": "Technique ID",
        "reasoning": "Detailed explanation of why this alert maps to this MITRE technique and adversary objective."
    }},
    "threat_intelligence": "Summary of VirusTotal / AbuseIPDB / OTX indicator results.",
    "risk_reasoning": "Detailed justification of calculated risk score.",
    "recommended_actions": ["Alert-specific investigation step 1", "Alert-specific investigation step 2"],
    "containment": ["Specific containment action 1", "Specific containment action 2"],
    "recovery": ["Specific recovery step 1"],
    "lessons_learned": ["Specific rule tuning recommendation"],
    "false_positive_probability": "High / Medium / Low (with explanation)",
    "next_steps": ["Immediate analyst step 1"]
}}
"""
