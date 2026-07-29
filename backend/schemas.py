from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentSchema(BaseModel):
    id: str = "000"
    name: str = "Unknown"
    ip: Optional[str] = None


class RuleSchema(BaseModel):
    id: str
    level: int = 0
    description: str
    groups: List[str] = Field(default_factory=list)


class NormalizedAlertSchema(BaseModel):
    timestamp: str
    rule_id: str
    severity: int
    description: str
    agent_name: str
    agent_ip: Optional[str] = ""
    location: Optional[str] = ""
    raw: Dict[str, Any] = Field(default_factory=dict)


class MitreMappingSchema(BaseModel):
    technique: str = "Unknown"
    name: str = "Unknown"
    tactic: str = "Unknown"


class ThreatIntelSchema(BaseModel):
    ip: str
    virustotal: Dict[str, Any] = Field(default_factory=dict)


class AIIncidentReportSchema(BaseModel):
    summary: str
    risk: str
    mitre: MitreMappingSchema
    observations: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class DashboardStatsSchema(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    agents: int = 0
