from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.platypus import KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self):
        os.makedirs('reports', exist_ok=True)
        self.cyber_red = colors.HexColor('#FB3640')
        self.deep_black = colors.HexColor('#0A0A0A')
        self.dark_gray = colors.HexColor('#1A1A2E')
        self.mid_gray = colors.HexColor('#333333')
        self.light_gray = colors.HexColor('#F5F5F5')
        self.white = colors.white
        self.sev_colors = {
            'Critical': colors.HexColor('#FB3640'),
            'High': colors.HexColor('#FF6B35'),
            'Medium': colors.HexColor('#FFB800'),
            'Low': colors.HexColor('#4CAF50'),
            'Info': colors.HexColor('#2196F3'),
        }

    def generate(self, session):
        scan_id = session['id'][:8]
        pdf_path = f"reports/vaultscan_report_{scan_id}.pdf"
        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []
        story += self._build_cover(session, styles)
        story += self._build_executive_summary(session, styles)
        story += self._build_vulnerability_table(session, styles)
        story += self._build_detailed_findings(session, styles)
        story += self._build_ai_insights(session, styles)
        story += self._build_footer_page(session, styles)
        doc.build(story)
        return pdf_path

    def _h1(self, text, styles):
        style = ParagraphStyle('h1', parent=styles['Normal'],
                               fontSize=24, textColor=self.cyber_red,
                               spaceAfter=12, fontName='Helvetica-Bold')
        return Paragraph(text, style)

    def _h2(self, text, styles):
        style = ParagraphStyle('h2', parent=styles['Normal'],
                               fontSize=16, textColor=self.deep_black,
                               spaceAfter=8, spaceBefore=16, fontName='Helvetica-Bold')
        return Paragraph(text, style)

    def _h3(self, text, styles):
        style = ParagraphStyle('h3', parent=styles['Normal'],
                               fontSize=13, textColor=self.dark_gray,
                               spaceAfter=6, spaceBefore=10, fontName='Helvetica-Bold')
        return Paragraph(text, style)

    def _body(self, text, styles, color=None):
        style = ParagraphStyle('body', parent=styles['Normal'],
                               fontSize=10, textColor=color or self.mid_gray,
                               spaceAfter=6, leading=14)
        return Paragraph(text, style)

    def _build_cover(self, session, styles):
        items = []
        items.append(Spacer(1, 1.5*inch))

        title_style = ParagraphStyle('cover_title', parent=styles['Normal'],
                                     fontSize=42, textColor=self.cyber_red,
                                     alignment=TA_CENTER, fontName='Helvetica-Bold')
        sub_style = ParagraphStyle('cover_sub', parent=styles['Normal'],
                                   fontSize=16, textColor=self.dark_gray,
                                   alignment=TA_CENTER, fontName='Helvetica')

        items.append(Paragraph("VAULTSCAN", title_style))
        items.append(Spacer(1, 0.2*inch))
        items.append(Paragraph("AI-Powered Security Assessment Report", sub_style))
        items.append(Spacer(1, 0.5*inch))
        items.append(HRFlowable(width="80%", thickness=2, color=self.cyber_red, hAlign='CENTER'))
        items.append(Spacer(1, 0.5*inch))

        ai = session.get('ai_analysis', {})
        risk_score = ai.get('risk_score', 0) if ai else 0
        grade = ai.get('scan_grade', 'N/A') if ai else 'N/A'

        meta_data = [
            ['Target URL', session.get('url', 'N/A')],
            ['Scan ID', session['id'][:16].upper()],
            ['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M UTC')],
            ['Risk Score', f"{risk_score}/100"],
            ['Security Grade', grade],
            ['Total Vulnerabilities', str(len(session.get('vulnerabilities', [])))],
        ]
        t = Table(meta_data, colWidths=[2.5*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.dark_gray),
            ('TEXTCOLOR', (0, 0), (0, -1), self.white),
            ('TEXTCOLOR', (1, 0), (1, -1), self.deep_black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (1, 0), (1, -1), [self.light_gray, self.white]),
            ('BOX', (0, 0), (-1, -1), 1, self.dark_gray),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#CCCCCC')),
        ]))
        items.append(t)
        items.append(Spacer(1, 1.5*inch))
        disclaimer_style = ParagraphStyle('disc', parent=styles['Normal'],
                                          fontSize=8, textColor=colors.gray,
                                          alignment=TA_CENTER)
        items.append(Paragraph("CONFIDENTIAL — For authorized security personnel only. Do not distribute.", disclaimer_style))
        items.append(Spacer(1, 0.5*inch))
        return items

    def _build_executive_summary(self, session, styles):
        items = []
        items.append(HRFlowable(width="100%", thickness=3, color=self.cyber_red))
        items.append(Spacer(1, 0.2*inch))
        items.append(self._h1("Executive Summary", styles))

        ai = session.get('ai_analysis', {}) or {}
        exec_sum = ai.get('executive_summary', {})
        if exec_sum.get('narrative'):
            items.append(self._body(exec_sum['narrative'], styles))
            items.append(Spacer(1, 0.2*inch))

        vulns = session.get('vulnerabilities', [])
        sev_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for v in vulns:
            sev_dist[v['severity']] = sev_dist.get(v['severity'], 0) + 1

        summary_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['CRITICAL', str(sev_dist['Critical']), 'Immediate Action'],
            ['HIGH', str(sev_dist['High']), 'Urgent'],
            ['MEDIUM', str(sev_dist['Medium']), 'Scheduled'],
            ['LOW', str(sev_dist['Low']), 'Backlog'],
            ['INFO', str(sev_dist['Info']), 'Informational'],
        ]
        t = Table(summary_data, colWidths=[2*inch, 1.5*inch, 3*inch])
        sev_bg = [self.cyber_red, colors.HexColor('#FF6B35'), colors.HexColor('#FFB800'),
                  colors.HexColor('#4CAF50'), colors.HexColor('#2196F3')]
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.dark_gray),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 1, self.dark_gray),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
            *[('TEXTCOLOR', (0, i+1), (0, i+1), sev_bg[i]) for i in range(5)],
        ]))
        items.append(t)
        items.append(Spacer(1, 0.3*inch))
        return items

    def _build_vulnerability_table(self, session, styles):
        items = []
        items.append(HRFlowable(width="100%", thickness=3, color=self.cyber_red))
        items.append(Spacer(1, 0.2*inch))
        items.append(self._h1("Vulnerability Summary", styles))

        vulns = session.get('vulnerabilities', [])
        if not vulns:
            items.append(self._body("No vulnerabilities found in this scan.", styles))
            return items

        table_data = [['ID', 'Vulnerability', 'Severity', 'CVSS', 'OWASP Category']]
        for v in vulns:
            table_data.append([
                v['id'],
                Paragraph(v['name'][:45], ParagraphStyle('cell', fontSize=8, leading=10)),
                v['severity'],
                str(v.get('cvss', 'N/A')),
                Paragraph(v.get('owasp_category', '')[:35], ParagraphStyle('cell', fontSize=8, leading=10)),
            ])

        t = Table(table_data, colWidths=[0.8*inch, 2.2*inch, 0.9*inch, 0.6*inch, 2.2*inch],
                  repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), self.dark_gray),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 1, self.dark_gray),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.light_gray, self.white]),
        ]
        sev_color_map = self.sev_colors
        for row_idx, v in enumerate(vulns, start=1):
            c = sev_color_map.get(v['severity'], colors.gray)
            style_cmds.append(('TEXTCOLOR', (2, row_idx), (2, row_idx), c))
            style_cmds.append(('FONTNAME', (2, row_idx), (2, row_idx), 'Helvetica-Bold'))
        t.setStyle(TableStyle(style_cmds))
        items.append(t)
        items.append(Spacer(1, 0.3*inch))
        return items

    def _build_detailed_findings(self, session, styles):
        items = []
        items.append(HRFlowable(width="100%", thickness=3, color=self.cyber_red))
        items.append(Spacer(1, 0.2*inch))
        items.append(self._h1("Detailed Findings", styles))

        vulns = session.get('vulnerabilities', [])
        ai = session.get('ai_analysis', {}) or {}
        fixes = ai.get('fix_suggestions', {})

        for v in vulns[:15]:
            sev_color = self.sev_colors.get(v['severity'], colors.gray)
            sev_style = ParagraphStyle('sev', fontSize=11, textColor=sev_color,
                                       fontName='Helvetica-Bold')
            finding_items = [
                Paragraph(f"[{v['id']}] {v['name']}", ParagraphStyle('finding_title',
                          fontSize=13, fontName='Helvetica-Bold', textColor=self.dark_gray)),
                Spacer(1, 0.05*inch),
                Paragraph(f"Severity: {v['severity']}  |  CVSS: {v.get('cvss', 'N/A')}  |  {v.get('owasp_category', '')}", sev_style),
                Spacer(1, 0.05*inch),
                self._body(f"<b>Endpoint:</b> {v.get('endpoint', 'N/A')}", styles),
                self._body(f"<b>Description:</b> {v.get('description', '')}", styles),
            ]
            if v.get('evidence'):
                finding_items.append(self._body(f"<b>Evidence:</b> {v['evidence']}", styles, color=colors.HexColor('#666666')))
            fix = fixes.get(v['id'])
            if fix and fix.get('steps'):
                finding_items.append(self._body("<b>Remediation Steps:</b>", styles))
                for step in fix['steps'][:3]:
                    finding_items.append(self._body(f"  • {step}", styles))
            finding_items.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#DDDDDD')))
            finding_items.append(Spacer(1, 0.15*inch))
            items += finding_items
        return items

    def _build_ai_insights(self, session, styles):
        items = []
        ai = session.get('ai_analysis', {}) or {}
        insights = ai.get('security_insights', [])
        if not insights:
            return items

        items.append(HRFlowable(width="100%", thickness=3, color=self.cyber_red))
        items.append(Spacer(1, 0.2*inch))
        items.append(self._h1("AI Security Insights", styles))
        for insight in insights:
            items.append(self._h3(f"{insight.get('icon', '•')} {insight.get('title', '')}", styles))
            items.append(self._body(insight.get('message', ''), styles))
            items.append(Spacer(1, 0.1*inch))
        return items

    def _build_footer_page(self, session, styles):
        items = []
        items.append(Spacer(1, 0.5*inch))
        items.append(HRFlowable(width="100%", thickness=3, color=self.cyber_red))
        items.append(Spacer(1, 0.2*inch))
        footer_style = ParagraphStyle('footer', parent=styles['Normal'],
                                      fontSize=9, textColor=colors.gray,
                                      alignment=TA_CENTER)
        items.append(Paragraph("Generated by VaultScan AI Security Platform", footer_style))
        items.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M UTC')}", footer_style))
        items.append(Paragraph("This report is confidential and intended for authorized personnel only.", footer_style))
        return items
