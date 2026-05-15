from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import AuditSession

SEVERITY_COLORS = {
    "High": colors.HexColor("#dc2626"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#64748b"),
}


def build_pdf(session: AuditSession) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, rightMargin=0.6 * inch, leftMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("AuditTitle", parent=styles["Title"], textColor=colors.HexColor("#111827"), spaceAfter=18)
    body: list = [Paragraph("AuditAI Smart Contract Audit", title)]
    body.append(Paragraph(f"Contract: <b>{session.contract_name}</b>", styles["BodyText"]))
    body.append(Paragraph(f"Pragma: <b>{session.pragma_version or 'not detected'}</b>", styles["BodyText"]))
    body.append(Spacer(1, 0.2 * inch))

    counts: dict[str, int] = {}
    for finding in session.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{severity}: {count}" for severity, count in sorted(counts.items())) or "No findings"
    body.append(Paragraph(f"Cover Summary: <b>{summary}</b>", styles["Heading2"]))
    body.append(Spacer(1, 0.2 * inch))

    for finding in session.findings:
        color = SEVERITY_COLORS.get(finding.severity, colors.HexColor("#64748b"))
        slither_description = escape(finding.slither_description or "")
        explanation = escape(finding.explanation or "")
        exploitability = escape(finding.exploitability or "")
        remediation = escape(finding.remediation_snippet or "")
        table = Table(
            [[finding.severity, finding.vulnerability_type, f"Line {finding.line_number or 'n/a'}"]],
            colWidths=[1.2 * inch, 4.2 * inch, 1.1 * inch],
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), color),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        body.append(table)
        body.append(Paragraph(f"<b>Slither:</b> {slither_description}", styles["BodyText"]))
        body.append(Paragraph(f"<b>Explanation:</b> {explanation}", styles["BodyText"]))
        body.append(Paragraph(f"<b>Exploitability:</b> {exploitability}", styles["BodyText"]))
        body.append(Paragraph(f"<b>Remediation:</b><br/><font face='Courier'>{remediation}</font>", styles["BodyText"]))
        body.append(Spacer(1, 0.22 * inch))

    doc.build(body)
    return buffer.getvalue()
