import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from database.db import get_db
from auth.rbac import admin_required, role_required
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


def log_audit_event(action: str, details: str):
    """
    Log an event to the SQLite audit_logs table.
    """
    conn = get_db()
    cursor = conn.cursor()
    user_info = session.get("user", {})
    username = user_info.get("username", "System")
    role = user_info.get("role", "Administrator")
    ip_addr = request.remote_addr or "127.0.0.1"

    cursor.execute(
        "INSERT INTO audit_logs (username, role, action, details, ip_address) VALUES (?, ?, ?, ?, ?);",
        (username, role, action, details, ip_addr)
    )
    conn.commit()
    conn.close()


@admin_bp.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "SOC Analyst")
        department = request.form.get("department", "SOC Operations")
        phone = request.form.get("phone", "")

        if not username or not email or not password:
            flash("Username, email, and password are required.", "danger")
        else:
            pass_hash = generate_password_hash(password)
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, role, department, phone) VALUES (?, ?, ?, ?, ?, ?);",
                    (username, email, pass_hash, role, department, phone)
                )
                conn.commit()
                log_audit_event("CREATE_USER", f"Created user '{username}' with role '{role}'")
                flash(f"Successfully created user account '{username}'.", "success")
            except Exception as e:
                flash(f"Failed to create user: {str(e)}", "danger")

    cursor.execute("SELECT id, username, email, role, status, department, created_at, last_login FROM users ORDER BY id DESC;")
    users_list = cursor.fetchall()
    conn.close()

    return render_template("admin_users.html", users=users_list)


@admin_bp.route("/users/<int:user_id>/status", methods=["POST"])
@admin_required
def toggle_user_status(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, status FROM users WHERE id = ?;", (user_id,))
    user = cursor.fetchone()
    if user:
        new_status = "Disabled" if user["status"] == "Active" else "Active"
        cursor.execute("UPDATE users SET status = ? WHERE id = ?;", (new_status, user_id))
        conn.commit()
        log_audit_event("UPDATE_USER_STATUS", f"Updated status of user '{user['username']}' to '{new_status}'")
        flash(f"Updated status of user '{user['username']}' to '{new_status}'.", "info")
    conn.close()
    return redirect(url_for("admin_bp.manage_users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user_account(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?;", (user_id,))
    user = cursor.fetchone()
    if user:
        if user["username"] == session.get("user", {}).get("username"):
            flash("Cannot delete your own active administrator account.", "warning")
        else:
            cursor.execute("DELETE FROM users WHERE id = ?;", (user_id,))
            conn.commit()
            log_audit_event("DELETE_USER", f"Deleted user account '{user['username']}'")
            flash(f"Deleted user account '{user['username']}'.", "success")
    conn.close()
    return redirect(url_for("admin_bp.manage_users"))


@admin_bp.route("/profile", methods=["GET", "POST"])
@role_required("Administrator", "SOC Manager", "SOC Analyst", "Read Only", "Auditor")
def profile():
    if request.method == "POST":
        new_email = request.form.get("email", "").strip()
        new_pass = request.form.get("new_password", "").strip()
        username = session.get("user", {}).get("username")

        conn = get_db()
        cursor = conn.cursor()

        if new_email:
            cursor.execute("UPDATE users SET email = ? WHERE username = ?;", (new_email, username))
        if new_pass:
            pass_hash = generate_password_hash(new_pass)
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?;", (pass_hash, username))

        conn.commit()
        conn.close()
        log_audit_event("UPDATE_PROFILE", f"User '{username}' updated profile credentials")
        flash("Profile updated successfully.", "success")

    return render_template("admin_profile.html")


@admin_bp.route("/audit-logs")
@admin_required
def view_audit_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, action, details, ip_address, timestamp FROM audit_logs ORDER BY id DESC LIMIT 100;")
    logs = cursor.fetchall()
    conn.close()
    return render_template("admin_audit_logs.html", logs=logs)
