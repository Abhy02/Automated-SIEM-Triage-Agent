from functools import wraps
import logging
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth.auth_service import authenticate

logger = logging.getLogger(__name__)

auth = Blueprint("auth", __name__)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            logger.info("Unauthorized access attempt. Redirecting to login.")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


def role_required(allowed_roles: list):
    """
    Decorator for checking user role permissions on routes.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("auth.login"))
            
            user_role = session["user"].get("role")
            if user_role not in allowed_roles and "SOC Admin" not in user_role:
                flash("Permission denied for this security workspace action.", "error")
                return redirect(url_for("dashboard.home"))
            
            return view(*args, **kwargs)
        return wrapper
    return decorator


@auth.route("/")
def index():
    return redirect(url_for("auth.login"))


@auth.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate(username, password)

        if user:
            session.clear()
            session["user"] = user
            flash("SOC Analyst session authenticated successfully.", "success")
            return redirect(url_for("dashboard.home"))

        flash("Invalid security credentials.", "error")

    return render_template("login.html")


@auth.route("/logout")
def logout():
    session.clear()
    flash("Session terminated successfully.", "success")
    return redirect(url_for("auth.login"))
