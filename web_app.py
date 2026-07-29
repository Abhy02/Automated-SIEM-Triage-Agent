import logging
import os
from flask import Flask, redirect, render_template, request, url_for
from config import Config
from database.db import init_db
from auth.setup_wizard import is_setup_required, setup_bp
from auth.admin_routes import admin_bp
from dashboard.routes import dashboard
from dashboard.utils import format_timestamp, severity_badge
from auth.routes import auth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("AISOC")

app = Flask(__name__)

app.config["SECRET_KEY"] = Config.SECRET_KEY

# Initialize Database Schema
init_db()

# Register Blueprints
app.register_blueprint(auth)
app.register_blueprint(dashboard)
app.register_blueprint(setup_bp)
app.register_blueprint(admin_bp)

# Jinja Filter Registrations
app.jinja_env.filters["severity"] = severity_badge
app.jinja_env.filters["datetime"] = format_timestamp


# First-Run Setup Redirection Middleware
@app.before_request
def check_first_run_setup():
    if request.path.startswith("/static") or request.path.startswith("/setup"):
        return None
    if is_setup_required():
        return redirect(url_for("setup_bp.setup"))


# Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:;"
    )
    return response


@app.errorhandler(404)
def page_not_found(e):
    return render_template("login.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Internal Server Error: %s", str(e))
    return render_template("login.html"), 500


if __name__ == "__main__":
    logger.info("Starting AISOC Enterprise Commercial Platform...")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
