import os
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import get_db, init_db
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

setup_bp = Blueprint("setup_bp", __name__)


def is_setup_required() -> bool:
    """
    Check if setup wizard is required (if no admin user exists in SQLite DB).
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users;")
    count = cursor.fetchone()[0]
    conn.close()
    return count == 0


@setup_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if not is_setup_required():
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        org_name = request.form.get("org_name", "AISOC Organization").strip()
        company_name = request.form.get("company_name", "Enterprise Security").strip()
        timezone = request.form.get("timezone", "Asia/Kolkata").strip()

        admin_user = request.form.get("admin_user", "admin").strip()
        admin_email = request.form.get("admin_email", "admin@aisoc.io").strip()
        admin_pass = request.form.get("admin_pass", "").strip()
        confirm_pass = request.form.get("confirm_pass", "").strip()

        if not admin_user or not admin_pass:
            flash("Administrator username and password are required.", "danger")
            return render_template("setup.html")

        if admin_pass != confirm_pass:
            flash("Passwords do not match.", "danger")
            return render_template("setup.html")

        # Create Admin User and Organization record in SQLite DB
        conn = get_db()
        cursor = conn.cursor()
        pass_hash = generate_password_hash(admin_pass)
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'Administrator');",
                (admin_user, admin_email, pass_hash)
            )
            cursor.execute(
                "INSERT INTO organization (name, company_name, timezone) VALUES (?, ?, ?);",
                (org_name, company_name, timezone)
            )
            conn.commit()
            logger.info("Created initial Organization '%s' and Administrator account: %s", org_name, admin_user)
        except Exception as e:
            flash(f"Error creating admin account: {str(e)}", "danger")
            conn.close()
            return render_template("setup.html")

        conn.close()

        # Generate .env File from Setup Inputs
        wazuh_host = request.form.get("wazuh_host", "https://192.168.1.61:55000")
        opensearch_host = request.form.get("opensearch_host", "https://192.168.1.61:9200")
        ollama_url = request.form.get("ollama_url", "http://localhost:11434/api/generate")
        vt_key = request.form.get("vt_key", "")

        env_content = f"""SECRET_KEY=aisoc-enterprise-secret-key-prod-2026-v4
DEMO_MODE=false
WAZUH_HOST={wazuh_host}
OPENSEARCH_HOST={opensearch_host}
OLLAMA_URL={ollama_url}
OLLAMA_MODEL=llama3.2:3b
VT_API_KEY={vt_key}
"""
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        try:
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(env_content)
        except Exception as e:
            logger.warning("Failed to write .env file: %s", str(e))

        flash("First-run setup completed successfully! Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup.html")
