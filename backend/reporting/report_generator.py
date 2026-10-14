import json
from typing import Dict, Any

from backend.models import ScanResult, SeverityLevel


class ReportGenerator:
    """
    Generates exportable Security Audit Reports in Markdown, JSON, and clean printable HTML format.
    """

    @staticmethod
    def to_json(result: ScanResult) -> str:
        return result.model_dump_json(indent=2)

    @staticmethod
    def to_markdown(result: ScanResult) -> str:
        md = []
        md.append(f"# Automated Web Security Audit Report")
        md.append(f"**Target URL:** `{result.target_url}`  ")
        md.append(f"**Domain:** `{result.domain}`  ")
        md.append(f"**Audit Date:** {result.started_at}  ")
        md.append(f"**Security Grade:** `{result.grade}` | **Score:** `{result.score}/100`  ")
        md.append(f"**Domain Ownership Verified:** {'✅ Yes' if result.is_domain_verified else '❌ No (Passive Audit Only)'}  ")
        md.append("\n---\n")

        # Summary Metrics
        s = result.findings_summary
        md.append("## Vulnerability & Misconfiguration Summary")
        md.append(f"- **Critical:** {s.critical}")
        md.append(f"- **High:** {s.high}")
        md.append(f"- **Medium:** {s.medium}")
        md.append(f"- **Low:** {s.low}")
        md.append(f"- **Info / Best Practice:** {s.info}")
        md.append(f"- **Total Findings:** {s.total}\n")

        # Executive Overview
        if result.executive_overview:
            md.append("## Executive Summary")
            md.append(result.executive_overview)
            md.append("\n---\n")

        # Detailed Findings
        md.append("## Detailed Technical Findings & Remediation Guide\n")

        for idx, f in enumerate(result.findings, start=1):
            sev_badge = {
                SeverityLevel.CRITICAL: "🔴 CRITICAL",
                SeverityLevel.HIGH: "🟠 HIGH",
                SeverityLevel.MEDIUM: "🟡 MEDIUM",
                SeverityLevel.LOW: "🔵 LOW",
                SeverityLevel.INFO: "⚪ INFO",
            }.get(f.severity, f.severity.value)

            md.append(f"### {idx}. [{sev_badge}] {f.name}")
            md.append(f"- **Category:** {f.category}")
            md.append(f"- **Endpoint:** `{f.endpoint}`")
            md.append(f"- **CVSS Score:** {f.cvss_score}{f' ({f.cvss_vector})' if f.cvss_vector else ''}")
            if f.cwe_id:
                md.append(f"- **CWE:** {f.cwe_id}")
            if f.owasp_category:
                md.append(f"- **OWASP Top 10:** {f.owasp_category}")
            md.append(f"- **Confidence:** {f.confidence}")
            md.append(f"\n**Description:**\n{f.description}\n")

            if f.evidence:
                md.append(f"**Evidence:**\n```\n{f.evidence}\n```\n")

            if f.request_proof:
                md.append(f"**Request Proof:**\n```http\n{f.request_proof}\n```\n")

            if f.response_proof:
                md.append(f"**Response Proof:**\n```http\n{f.response_proof}\n```\n")

            if f.impact:
                md.append(f"**Business & Security Impact:**\n{f.impact}\n")

            if f.remediation_summary:
                md.append(f"**Remediation Steps:**\n{f.remediation_summary}\n")

            if f.remediation_code:
                md.append("**Implementation Code Patches:**")
                for lang, code_snippet in f.remediation_code.items():
                    md.append(f"*{lang.upper()} Configuration:*\n```{lang}\n{code_snippet}\n```\n")

            if f.references:
                md.append("**References:**")
                for ref in f.references:
                    md.append(f"- <{ref}>")
                md.append("")

            md.append("\n---\n")

        return "\n".join(md)

    @staticmethod
    def to_printable_html(result: ScanResult) -> str:
        s = result.findings_summary
        grade_color = {
            "A+": "#10b981", "A": "#10b981", "B": "#3b82f6",
            "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"
        }.get(result.grade, "#6b7280")

        findings_html = []
        for idx, f in enumerate(result.findings, 1):
            sev_color = {
                "CRITICAL": "#ef4444", "HIGH": "#f97316",
                "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#6b7280"
            }.get(f.severity.value, "#6b7280")

            code_blocks = ""
            if f.remediation_code:
                for lang, snippet in f.remediation_code.items():
                    code_blocks += f"<div class='code-card'><strong>{lang.upper()}:</strong><pre><code>{snippet}</code></pre></div>"

            proof_blocks = ""
            if f.request_proof or f.response_proof:
                proof_blocks = f"""
                <div style="margin-top:12px; background:#0b0f19; padding:12px; border-radius:6px; border:1px solid #334155;">
                    <div style="font-weight:700; color:#38bdf8; margin-bottom:6px;">🔬 Technical Request & Response Proof:</div>
                    {f"<div style='font-size:12px; color:#94a3b8;'>REQUEST:</div><pre style='margin:4px 0 8px 0;'><code>{f.request_proof}</code></pre>" if f.request_proof else ""}
                    {f"<div style='font-size:12px; color:#94a3b8;'>RESPONSE:</div><pre style='margin:4px 0;'><code>{f.response_proof}</code></pre>" if f.response_proof else ""}
                </div>
                """

            findings_html.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="sev-badge" style="background-color: {sev_color}">{f.severity.value}</span>
                    <span class="finding-title">{idx}. {f.name}</span>
                    {f"<span style='background:#1e293b; color:#38bdf8; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'>{f.cwe_id}</span>" if f.cwe_id else ""}
                    <span class="finding-cat">{f.category}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Endpoint:</strong> <code>{f.endpoint}</code></p>
                    {f"<p><strong>OWASP Top 10:</strong> {f.owasp_category}</p>" if f.owasp_category else ""}
                    <p><strong>Description:</strong> {f.description}</p>
                    {proof_blocks}
                    {f"<p><strong>Impact:</strong> {f.impact}</p>" if f.impact else ""}
                    {f"<p><strong>Remediation:</strong> {f.remediation_summary}</p>" if f.remediation_summary else ""}
                    {f"<div class='evidence'><strong>Evidence:</strong><pre>{f.evidence}</pre></div>" if f.evidence else ""}
                    {f"<div class='code-section'><strong>Remediation Code:</strong>{code_blocks}</div>" if code_blocks else ""}
                </div>
            </div>
            """)

        all_findings_str = "\n".join(findings_html)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - {result.domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; }}
        .title h1 {{ margin: 0 0 8px 0; font-size: 28px; color: #38bdf8; }}
        .meta {{ color: #94a3b8; font-size: 14px; line-height: 1.6; }}
        .score-box {{ text-align: center; border: 3px solid {grade_color}; padding: 15px 30px; border-radius: 12px; background: #1e293b; }}
        .score-grade {{ font-size: 48px; font-weight: 800; color: {grade_color}; margin: 0; }}
        .score-val {{ color: #94a3b8; font-size: 14px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 30px; }}
        .metric-card {{ background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .metric-val {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
        .metric-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; }}
        .exec-summary {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 20px; border-radius: 8px; margin-bottom: 30px; line-height: 1.7; }}
        .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 20px; background: #0f172a; border-bottom: 1px solid #334155; }}
        .sev-badge {{ color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 800; text-transform: uppercase; }}
        .finding-title {{ font-size: 16px; font-weight: 600; flex-grow: 1; }}
        .finding-cat {{ color: #94a3b8; font-size: 12px; }}
        .finding-body {{ padding: 20px; font-size: 14px; line-height: 1.6; }}
        pre {{ background: #0b0f19; padding: 12px; border-radius: 6px; overflow-x: auto; color: #38bdf8; border: 1px solid #1e293b; }}
        .code-card {{ margin-top: 10px; }}
        @media print {{
            body {{ background: white !important; color: black !important; }}
            .metric-card, .finding-card, .exec-summary, .score-box {{ background: white !important; border-color: #cbd5e1 !important; color: black !important; }}
            pre {{ background: #f1f5f9 !important; color: #0f172a !important; border: 1px solid #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <h1>🛡️ Web Security Audit Report</h1>
                <div class="meta">
                    <div><strong>Target:</strong> {result.target_url}</div>
                    <div><strong>Domain:</strong> {result.domain}</div>
                    <div><strong>Audit Date:</strong> {result.started_at}</div>
                    <div><strong>Ownership Verified:</strong> {'Yes' if result.is_domain_verified else 'No (Passive Public Audit)'}</div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-grade">{result.grade}</div>
                <div class="score-val">{result.score}/100 Score</div>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card"><div class="metric-val" style="color: #ef4444">{s.critical}</div><div class="metric-label">Critical</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #f97316">{s.high}</div><div class="metric-label">High</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #f59e0b">{s.medium}</div><div class="metric-label">Medium</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #3b82f6">{s.low}</div><div class="metric-label">Low</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #6b7280">{s.info}</div><div class="metric-label">Info</div></div>
        </div>

        {f"<div class='exec-summary'><h2>Executive Summary</h2><p>{result.executive_overview.replace(chr(10), '<br>')}</p></div>" if result.executive_overview else ""}

        <h2>Technical Findings ({len(result.findings)})</h2>
        {all_findings_str}
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def to_soc2_report(result: ScanResult, org: Any = "Enterprise Organization") -> bytes:
        """Generates an executive SOC 2 compliance mapping report in PDF format."""
        from backend.reporting.compliance import ComplianceEvaluator, generate_compliance_pdf
        org_name = org.name if hasattr(org, "name") else str(org)
        evaluation = ComplianceEvaluator.evaluate_soc2(result)
        return generate_compliance_pdf(evaluation, result, org_name)

    @staticmethod
    def to_iso27001_report(result: ScanResult, org: Any = "Enterprise Organization") -> bytes:
        """Generates an executive ISO 27001:2022 compliance mapping report in PDF format."""
        from backend.reporting.compliance import ComplianceEvaluator, generate_compliance_pdf
        org_name = org.name if hasattr(org, "name") else str(org)
        evaluation = ComplianceEvaluator.evaluate_iso27001(result)
        return generate_compliance_pdf(evaluation, result, org_name)

