import io
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from .excel_generator import (
    get_category_from_id,
    get_checkpoint_name,
    CATEGORY_HIERARCHY,
    SEVERITY_HIERARCHY,
)


def generate_pdf_report(scan_data, user_name, project_id):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )

    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=8
    )

    category_style = ParagraphStyle(
        'CategoryHeader',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#4F46E5'),
        spaceBefore=10,
        spaceAfter=4
    )

    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0F172A')
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    remediation_style = ParagraphStyle(
        'RemediationText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#0284C7')
    )

    story = []

    # Title
    story.append(Paragraph("Cloud Security Audit Report", title_style))
    scan_date_str = datetime.utcnow().strftime("%B %d, %Y - %H:%M UTC")
    story.append(Paragraph(f"Project: <b>{project_id}</b> &nbsp;|&nbsp; Generated for: <b>{user_name}</b> &nbsp;|&nbsp; Date: {scan_date_str}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#4F46E5'), spaceAfter=15))

    # Vulnerabilities
    vulnerabilities = scan_data.get("vulnerabilities")
    if vulnerabilities is None:
        findings_raw = scan_data.get("findings", [])
        if isinstance(findings_raw, str):
            try:
                vulnerabilities = json.loads(findings_raw)
            except Exception:
                vulnerabilities = []
        elif isinstance(findings_raw, list):
            vulnerabilities = findings_raw
        else:
            vulnerabilities = []

    score = scan_data.get("score", 100)
    scanned = scan_data.get("scannedResources") or scan_data.get("scanned", 0)
    crit_count = scan_data.get("criticalCount") or len([v for v in vulnerabilities if v.get("severity") == "Critical"])
    high_count = scan_data.get("highCount") or len([v for v in vulnerabilities if v.get("severity") == "High"])
    med_count = scan_data.get("mediumCount") or len([v for v in vulnerabilities if v.get("severity") == "Medium"])
    low_count = (scan_data.get("lowCount") or 0) + len([v for v in vulnerabilities if v.get("severity") == "Low"])

    # Score Card / Executive Summary Table
    score_color = '#22C55E' if score >= 80 else ('#EAB308' if score >= 60 else '#EF4444')
    summary_data = [
        [
            Paragraph(f"<font size='28' color='{score_color}'><b>{score}%</b></font><br/><font size='9' color='#64748B'>Security Score</font>", ParagraphStyle('ScoreCell', alignment=1)),
            Paragraph(f"<font size='16' color='#0F172A'><b>{scanned}</b></font><br/><font size='8' color='#64748B'>Scanned Resources</font>", ParagraphStyle('MetricCell', alignment=1)),
            Paragraph(f"<font size='16' color='#EF4444'><b>{crit_count}</b></font><br/><font size='8' color='#64748B'>Critical</font>", ParagraphStyle('MetricCell', alignment=1)),
            Paragraph(f"<font size='16' color='#F97316'><b>{high_count}</b></font><br/><font size='8' color='#64748B'>High</font>", ParagraphStyle('MetricCell', alignment=1)),
            Paragraph(f"<font size='16' color='#EAB308'><b>{med_count}</b></font><br/><font size='8' color='#64748B'>Medium</font>", ParagraphStyle('MetricCell', alignment=1)),
            Paragraph(f"<font size='16' color='#22C55E'><b>{low_count}</b></font><br/><font size='8' color='#64748B'>Low</font>", ParagraphStyle('MetricCell', alignment=1)),
        ]
    ]

    summary_table = Table(summary_data, colWidths=[110, 80, 80, 80, 80, 80])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Findings Breakdown
    story.append(Paragraph("Detailed Audit Findings", section_style))

    if not vulnerabilities:
        story.append(Paragraph("🎉 No security vulnerabilities or misconfigurations detected! All audited resources comply with baseline benchmarks.", body_style))
    else:
        # Group by Category
        findings_by_cat = {}
        for v in vulnerabilities:
            cat = get_category_from_id(v.get("id", ""))
            findings_by_cat.setdefault(cat, []).append(v)

        sorted_categories = sorted(
            findings_by_cat.keys(),
            key=lambda c: (CATEGORY_HIERARCHY.get(c, 99), c)
        )

        sev_badge_colors = {
            "Critical": "#EF4444",
            "High": "#F97316",
            "Medium": "#EAB308",
            "Low": "#22C55E",
        }

        for cat_name in sorted_categories:
            cat_findings = sorted(
                findings_by_cat[cat_name],
                key=lambda f: (SEVERITY_HIERARCHY.get(f.get("severity", "Medium"), 9), f.get("id", ""))
            )
            story.append(Paragraph(f"{cat_name} ({len(cat_findings)} findings)", category_style))

            table_rows = [
                [
                    Paragraph("<b>Resource & ID</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white)),
                    Paragraph("<b>Severity</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white, alignment=1)),
                    Paragraph("<b>Issue & Remediation</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white))
                ]
            ]

            for f in cat_findings:
                sev = f.get("severity", "Medium")
                badge_col = sev_badge_colors.get(sev, "#64748B")

                res_info = f"<b>{f.get('resource', 'Unknown')}</b><br/><font color='#64748B' size='7'>{f.get('id', '')}</font>"
                sev_info = f"<font color='{badge_col}'><b>{sev}</b></font>"
                issue_info = f"<b>Issue:</b> {f.get('issue', '')}<br/><font color='#0284C7'><b>Remediation:</b> {f.get('remediation', '')}</font>"

                table_rows.append([
                    Paragraph(res_info, body_style),
                    Paragraph(sev_info, ParagraphStyle('SevCell', alignment=1)),
                    Paragraph(issue_info, body_style)
                ])

            cat_table = Table(table_rows, colWidths=[140, 65, 305])
            cat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))

            story.append(cat_table)
            story.append(Spacer(1, 12))

    doc.build(story)
    return buffer.getvalue()
