import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

REPORTS_PDF_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "pdf")


def generate_incident_pdf(investigation_data: dict) -> str:
    """
    Generate a commercial-grade incident investigation PDF report using ReportLab.
    Returns absolute file path to the generated PDF.
    """
    os.makedirs(REPORTS_PDF_DIR, exist_ok=True)

    doc_id = investigation_data.get("doc_id", "INCIDENT-001")
    filename = f"AISOC_Incident_Report_{doc_id}.pdf"
    filepath = os.path.join(REPORTS_PDF_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#E50914')
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        textColor=colors.HexColor('#64748B')
    )

    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    story = []

    # Header Title Banner
    story.append(Paragraph("AISOC ENTERPRISE | INCIDENT INVESTIGATION REPORT", title_style))
    story.append(Paragraph(f"Autonomous SIEM Triage Platform • Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#E50914'), spaceAfter=15))

    # Incident Overview Table
    alert_info = investigation_data.get("alert", {})
    report_info = investigation_data.get("report", {})
    mitre_info = investigation_data.get("mitre", {})

    meta_data = [
        [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(str(doc_id), body_style), Paragraph("<b>Risk Level:</b>", body_style), Paragraph(str(investigation_data.get("risk", "High")), body_style)],
        [Paragraph("<b>Rule ID:</b>", body_style), Paragraph(str(alert_info.get("rule_id", "N/A")), body_style), Paragraph("<b>Confidence:</b>", body_style), Paragraph(f"{report_info.get('confidence_score', 94)}%", body_style)],
        [Paragraph("<b>Agent Name:</b>", body_style), Paragraph(str(alert_info.get("agent_name", "Unknown")), body_style), Paragraph("<b>Agent IP:</b>", body_style), Paragraph(str(alert_info.get("agent_ip", "N/A")), body_style)],
        [Paragraph("<b>MITRE TTP:</b>", body_style), Paragraph(f"{mitre_info.get('technique', 'N/A')} - {mitre_info.get('name', 'N/A')}", body_style), Paragraph("<b>Tactic:</b>", body_style), Paragraph(str(mitre_info.get("tactic", "N/A")), body_style)],
    ]

    t_meta = Table(meta_data, colWidths=[90, 180, 90, 180])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    # Executive Summary Section
    story.append(Paragraph("1. Executive Summary", heading2_style))
    summary_text = report_info.get("summary", alert_info.get("description", "Security incident detected."))
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # Attack Root Cause & Analysis
    story.append(Paragraph("2. Root Cause & Threat Analysis", heading2_style))
    root_cause = report_info.get("root_cause", f"Detection of Wazuh rule #{alert_info.get('rule_id')} on host '{alert_info.get('agent_name')}'")
    story.append(Paragraph(f"<b>Root Cause:</b> {root_cause}", body_style))
    likely_obj = report_info.get("likely_objective", "Potential unauthorized endpoint state modification")
    story.append(Paragraph(f"<b>Likely Adversary Objective:</b> {likely_obj}", body_style))
    story.append(Spacer(1, 10))

    # Recommended Response Playbook
    story.append(Paragraph("3. Recommended Action Playbook", heading2_style))
    recs = report_info.get("recommendations", ["Review endpoint process logs.", "Validate user authentication events."])
    for rec in recs:
        story.append(Paragraph(f"• {rec}", body_style))
    story.append(Spacer(1, 10))

    # Digital AI Signature
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CBD5E1'), spaceBefore=15, spaceAfter=10))
    story.append(Paragraph("<i>Electronically Generated & Certified by AISOC Autonomous Engine v4.0</i>", subtitle_style))

    doc.build(story)
    return filepath
