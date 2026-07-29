from dataclasses import dataclass


@dataclass
class Alert:

    timestamp: str
    rule_id: int
    severity: int
    description: str

    agent_name: str
    agent_ip: str

    location: str

    raw: dict
    
def normalize(alert: dict) -> Alert:
    """
    Convert a raw Wazuh alert into a normalized object.
    """

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    return Alert(
        timestamp=alert.get("@timestamp", ""),
        rule_id=rule.get("id", 0),
        severity=rule.get("level", 0),
        description=rule.get("description", ""),

        agent_name=agent.get("name", "Unknown"),
        agent_ip=agent.get("ip", ""),

        location=alert.get("location", ""),

        raw=alert,
    )
