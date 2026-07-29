from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    ADMIN = "SOC Admin"
    TIER3_ANALYST = "Senior SOC Analyst"
    TIER1_ANALYST = "SOC Analyst"
    AUDITOR = "Security Auditor"


class UserPermission(str, Enum):
    VIEW_DASHBOARD = "dashboard:view"
    VIEW_ALERTS = "alerts:view"
    INVESTIGATE_INCIDENT = "incident:investigate"
    EXECUTE_REMEDIATION = "remediation:execute"
    MANAGE_DETECTIONS = "detections:manage"
    ADMIN_SETTINGS = "admin:settings"


ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        UserPermission.VIEW_DASHBOARD,
        UserPermission.VIEW_ALERTS,
        UserPermission.INVESTIGATE_INCIDENT,
        UserPermission.EXECUTE_REMEDIATION,
        UserPermission.MANAGE_DETECTIONS,
        UserPermission.ADMIN_SETTINGS,
    ],
    UserRole.TIER3_ANALYST: [
        UserPermission.VIEW_DASHBOARD,
        UserPermission.VIEW_ALERTS,
        UserPermission.INVESTIGATE_INCIDENT,
        UserPermission.EXECUTE_REMEDIATION,
        UserPermission.MANAGE_DETECTIONS,
    ],
    UserRole.TIER1_ANALYST: [
        UserPermission.VIEW_DASHBOARD,
        UserPermission.VIEW_ALERTS,
        UserPermission.INVESTIGATE_INCIDENT,
    ],
    UserRole.AUDITOR: [
        UserPermission.VIEW_DASHBOARD,
        UserPermission.VIEW_ALERTS,
    ],
}


class User(BaseModel):
    username: str
    email: Optional[str] = "analyst@aisoc.enterprise"
    role: UserRole = UserRole.TIER1_ANALYST
    permissions: List[UserPermission] = Field(default_factory=list)
    is_active: bool = True

    def has_permission(self, permission: UserPermission) -> bool:
        return permission in self.permissions or permission in ROLE_PERMISSIONS.get(self.role, [])
