from functools import wraps
from flask import session, redirect, url_for, flash, abort

# Role Permission Matrix
ROLE_PERMISSIONS = {
    "Administrator": [
        "dashboard", "investigation", "threat_intel", "mitre",
        "reports", "copilot", "export_reports", "delete_reports",
        "settings", "user_management", "audit_logs"
    ],
    "SOC Manager": [
        "dashboard", "investigation", "threat_intel", "mitre",
        "reports", "copilot", "export_reports", "delete_reports"
    ],
    "SOC Analyst": [
        "dashboard", "investigation", "threat_intel", "mitre",
        "reports", "copilot"
    ],
    "Read Only": [
        "dashboard", "investigation", "reports"
    ],
    "Auditor": [
        "dashboard", "reports", "export_reports", "audit_logs"
    ]
}


def check_permission(role: str, permission: str) -> bool:
    """
    Check if a specific role possesses a permission scope.
    """
    allowed_permissions = ROLE_PERMISSIONS.get(role, [])
    return permission in allowed_permissions


def role_required(*allowed_roles):
    """
    Decorator to restrict Flask route execution to specified roles.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                flash("Authentication required to access this resource.", "warning")
                return redirect(url_for("auth.login"))

            user_role = session["user"].get("role", "SOC Analyst")
            if allowed_roles and user_role not in allowed_roles:
                flash(f"Access Denied: Role '{user_role}' is not authorized to access this page.", "danger")
                return redirect(url_for("dashboard.home"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return role_required("Administrator")(f)


def manager_required(f):
    return role_required("Administrator", "SOC Manager")(f)


def analyst_required(f):
    return role_required("Administrator", "SOC Manager", "SOC Analyst")(f)


def auditor_required(f):
    return role_required("Administrator", "SOC Manager", "Auditor")(f)
