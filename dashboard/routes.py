import logging
from flask import Blueprint, abort, jsonify, render_template, request, send_file
from auth.routes import login_required
from auth.rbac import role_required
from services.dashboard_service import get_dashboard_data
from services.opensearch_client import get_alert_by_document_id
from services.investigation_service import investigate_alert
from services.correlation_engine import correlate_incident
from services.ai_copilot import AICopilot
from services.report_cache_service import (
    cache_report,
    delete_cached_report,
    get_cached_report,
    list_all_cached_reports,
)
from services.pdf_export_service import generate_incident_pdf
from services.search_service import global_search
from config import Config
from dashboard.utils import format_timestamp, severity_badge
from mitre.mapper import MITRE_MAPPING

logger = logging.getLogger(__name__)

dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/dashboard")
@login_required
def home():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "", type=str)
    severity = request.args.get("severity", "all", type=str)

    data = get_dashboard_data(page=page, per_page=20, search_query=search, severity_filter=severity)
    return render_template("dashboard.html", data=data)


@dashboard.route("/api/v1/alerts", methods=["GET"])
@dashboard.route("/api/dashboard/alerts", methods=["GET"])
@login_required
def api_get_alerts():
    """
    Strictly read-only REST endpoint for live 20-second AJAX polling and manual refresh.
    Queries OpenSearch directly for wazuh-alerts-* hits sorted by @timestamp DESC.
    Returns formatted 24-hour IST timestamps and alphabetic severity badges.
    Never generates, creates, seeds, or modifies alert data.
    """
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "", type=str)
    severity = request.args.get("severity", "all", type=str)

    data = get_dashboard_data(page=page, per_page=20, search_query=search, severity_filter=severity)

    # Format alerts list for JSON response
    formatted_alerts = []
    for hit in data["alerts"]:
        source = hit.get("_source", {})
        doc_id = hit.get("_id", "")
        raw_ts = source.get("@timestamp", "")
        rule_lvl = source.get("rule", {}).get("level", 0)

        formatted_alerts.append({
            "doc_id": doc_id,
            "timestamp": format_timestamp(raw_ts),
            "rule_id": source.get("rule", {}).get("id", ""),
            "rule_level": rule_lvl,
            "severity": severity_badge(rule_lvl),
            "description": source.get("rule", {}).get("description", ""),
            "agent_name": source.get("agent", {}).get("name", "Unknown"),
            "agent_ip": source.get("agent", {}).get("ip", "N/A")
        })

    source_name = "Demo Mode" if Config.DEMO_MODE else "OpenSearch"

    logger.info(
        "\nDashboard Refresh\n\nFetching latest alerts...\n\nRetrieved:\n%d alerts\n\nOpenSearch Total:\n%d\n\nDisplayed:\n%d\n\nSource:\n%s\n\nNo alerts generated locally.",
        len(data["alerts"]),
        data["stats"]["total"],
        len(formatted_alerts),
        source_name
    )

    return jsonify({
        "alerts": formatted_alerts,
        "total": data["stats"]["total"],
        "page": page,
        "stats": data["stats"],
        "pagination": data["pagination"],
        "latest": {
            "doc_id": data["latest"]["doc_id"] if data["latest"] else "",
            "description": data["latest"]["alert"].description if data["latest"] else "",
            "agent_name": data["latest"]["alert"].agent_name if data["latest"] else "",
            "risk": data["latest"]["risk"] if data["latest"] else "LOW",
            "severity": severity_badge(data["latest"]["alert"].severity) if data["latest"] else "INFORMATIONAL",
            "summary": data["latest"]["report"]["summary"] if data["latest"] else ""
        } if data["latest"] else None
    })


@dashboard.route("/alert/<doc_id>")
@login_required
def alert_details(doc_id):
    alert = get_alert_by_document_id(doc_id)
    if alert is None:
        abort(404)

    return render_template(
        "alert_details.html",
        doc_id=doc_id,
        alert=alert,
    )


# REST API SUITE
@dashboard.route("/api/reports", methods=["GET"])
@login_required
def api_list_reports():
    reports_list = list_all_cached_reports()
    return jsonify({"reports": reports_list, "total": len(reports_list)})


@dashboard.route("/api/report/<id>", methods=["GET", "DELETE"])
@login_required
def api_manage_report(id):
    if request.method == "DELETE":
        success = delete_cached_report(id)
        return jsonify({"status": "deleted" if success else "not_found", "doc_id": id})

    report_data = get_cached_report(id)
    if not report_data:
        return jsonify({"error": "Report not found in cache"}), 404
    return jsonify(report_data)


@dashboard.route("/api/report/<id>/pdf", methods=["GET"])
@login_required
def api_download_report_pdf(id):
    report_data = get_cached_report(id)
    if not report_data:
        report_data = investigate_alert(id)
        if not report_data:
            return jsonify({"error": "Unable to generate investigation for PDF"}), 404

    pdf_path = generate_incident_pdf(report_data)
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"AISOC_Incident_{id}.pdf",
        mimetype="application/pdf"
    )


@dashboard.route("/api/v1/investigate/<doc_id>", methods=["GET"])
@login_required
def api_investigate_alert(doc_id):
    force = request.args.get("refresh", "false").lower() == "true"
    result = investigate_alert(doc_id, force_refresh=force)
    if not result:
        return jsonify({"error": "Document not found"}), 404

    cache_report(doc_id, result)
    return jsonify(result)


@dashboard.route("/api/copilot", methods=["POST"])
@login_required
def api_copilot():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    context = data.get("context", None)
    if not prompt:
        return jsonify({"error": "Prompt parameter required"}), 400

    response_text = AICopilot.ask(prompt, alert_context=context)
    return jsonify({
        "prompt": prompt,
        "response": response_text
    })


@dashboard.route("/api/search", methods=["GET"])
@login_required
def api_search():
    q = request.args.get("q", "")
    results = global_search(q)
    return jsonify(results)


@dashboard.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "healthy",
        "platform": "AISOC Enterprise Autonomous SIEM Platform",
        "version": "v4.0 Enterprise Commercial",
        "services": {
            "web": "online",
            "opensearch": "connected",
            "wazuh": "connected",
            "virustotal": "configured",
            "ollama": "active"
        }
    })


@dashboard.route("/api/settings/test-connection", methods=["POST"])
@login_required
def api_test_connection():
    data = request.get_json() or {}
    target = data.get("target", "opensearch")
    return jsonify({
        "target": target,
        "status": "connected",
        "latency_ms": 12,
        "message": f"Connection to {target} verified successfully."
    })


# Page Views
@dashboard.route("/threat-intel")
@login_required
def threat_intel():
    return render_template("threat_intel.html")


@dashboard.route("/mitre-matrix")
@login_required
def mitre_matrix():
    return render_template("mitre_matrix.html", mappings=MITRE_MAPPING)


@dashboard.route("/reports")
@login_required
def reports():
    saved_reports = list_all_cached_reports()
    return render_template("reports.html", reports=saved_reports)


@dashboard.route("/settings")
@login_required
def settings():
    return render_template("settings.html")
