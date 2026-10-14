import os
import json
from typing import List, Dict, Optional, Any

from backend.models import Finding, ScanResult, SeverityLevel


class AIRemediationEngine:
    """
    AI Remediation Layer:
    1. Parses raw finding data and context (headers, evidence).
    2. Deduplicates false-positives and groups overlapping alerts.
    3. Enriches findings with business impact analysis and framework-specific patch code.
    4. Generates an Executive Overview and Developer Remediation Blueprint.
    Supports Google Gemini API with smart fallback expert heuristics.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    async def analyze_and_enrich(self, scan_result: ScanResult, framework_hint: str = "auto") -> ScanResult:
        if not scan_result.findings:
            scan_result.executive_overview = (
                "No security anomalies or misconfigurations were detected during this audit. "
                "The target demonstrates strong baseline security hygiene across SSL/TLS and security headers."
            )
            scan_result.ai_summary = "All checks passed successfully."
            return scan_result

        # Try live LLM via Google Gemini SDK if API key available
        if self.api_key:
            try:
                enriched = await self._run_gemini_enrichment(scan_result, framework_hint)
                if enriched:
                    return enriched
            except Exception as e:
                # Log error and fall through to built-in expert remediation synthesizer
                print(f"[AIRemediationEngine] Gemini API call exception: {e}")

        # Fallback to local expert remediation synthesizer
        return self._run_expert_heuristic_enrichment(scan_result, framework_hint)

    async def _run_gemini_enrichment(self, scan_result: ScanResult, framework_hint: str) -> Optional[ScanResult]:
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            # Prepare structured findings payload
            findings_data = [
                {
                    "id": f.id,
                    "name": f.name,
                    "category": f.category,
                    "severity": f.severity.value,
                    "endpoint": f.endpoint,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in scan_result.findings
            ]

            prompt = f"""
You are a Principal Application Security Architect and DAST Remediation Expert.
Analyze the following raw security findings from a web audit on target {scan_result.target_url} (Domain: {scan_result.domain}).

Preferred tech stack / framework hint: {framework_hint}

Raw Findings JSON:
{json.dumps(findings_data, indent=2)}

Task:
1. Deduplicate any redundant findings and identify potential false positives.
2. Produce a professional "Executive Summary" (3-4 concise paragraphs) explaining the overall threat profile, compliance impact (OWASP Top 10, PCI-DSS, GDPR), and immediate priorities.
3. For each finding, generate:
   - A crisp business risk explanation.
   - Actionable remediation advice.
   - Precise copy-pasteable configuration or code patches for the relevant frameworks (Nginx, Express, Django/FastAPI).

Return your response strictly as a JSON object adhering to this schema:
{{
  "executive_overview": "Comprehensive executive summary text...",
  "findings_enrichment": [
    {{
      "id": "FINDING_ID",
      "impact": "Detailed business impact statement...",
      "remediation_summary": "Actionable step-by-step fix...",
      "remediation_code": {{
        "nginx": "nginx configuration snippet",
        "express": "Node.js Express snippet",
        "django": "Python Django settings snippet",
        "fastapi": "FastAPI middleware snippet"
      }}
    }}
  ]
}}
"""

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )

            result_json = json.loads(response.text)

            scan_result.executive_overview = result_json.get("executive_overview")
            enrichment_map = {item["id"]: item for item in result_json.get("findings_enrichment", [])}

            for finding in scan_result.findings:
                if finding.id in enrichment_map:
                    enr = enrichment_map[finding.id]
                    if enr.get("impact"):
                        finding.impact = enr["impact"]
                    if enr.get("remediation_summary"):
                        finding.remediation_summary = enr["remediation_summary"]
                    if enr.get("remediation_code"):
                        finding.remediation_code.update(enr["remediation_code"])

            scan_result.ai_summary = f"Audit synthesized by Gemini 2.5 Flash. Total {len(scan_result.findings)} findings evaluated."
            return scan_result

        except Exception as e:
            print(f"[AIRemediationEngine] Error during Gemini generation: {e}")
            return None

    def _run_expert_heuristic_enrichment(self, scan_result: ScanResult, framework_hint: str) -> ScanResult:
        """
        Deterministic, expert-grade remediation generator for offline or keyless operation.
        Ensures high-fidelity, copy-pasteable fixes and executive briefs without waiting for external API quotas.
        """
        crit_count = scan_result.findings_summary.critical
        high_count = scan_result.findings_summary.high
        med_count = scan_result.findings_summary.medium

        # Synthesize Executive Overview
        risk_level = "CRITICAL" if crit_count > 0 else ("ELEVATED" if high_count > 0 else ("MODERATE" if med_count > 0 else "LOW"))
        
        overview_lines = [
            f"### Executive Security Assessment for {scan_result.domain}",
            f"**Overall Posture: {risk_level} (Score: {scan_result.score}/100 - Grade: {scan_result.grade})**",
            "",
            f"The automated security evaluation identified {len(scan_result.findings)} notable observations across the target's public surface. "
            f"This includes {crit_count} Critical, {high_count} High, and {med_count} Medium severity issues requiring prioritization.",
        ]

        if crit_count > 0:
            overview_lines.append(
                "**Urgent Attention Required:** Critical findings such as exposed environment secrets or severe CORS misconfigurations "
                "allow unauthorized third parties to bypass access controls or extract backend data without authentication. Immediate patch deployment is strongly advised."
            )
        elif high_count > 0:
            overview_lines.append(
                "**Key Recommendations:** High-priority items include missing Content Security Policies (CSP) and SSL/TLS cipher or expiration warnings. "
                "These leave user sessions susceptible to cross-site scripting (XSS) and traffic interception on hostile networks."
            )
        else:
            overview_lines.append(
                "**Defense-in-Depth:** The application implements primary transport encryption. Addressing the flagged HTTP security headers "
                "will align the application with modern browser hardening guidelines and OWASP Top 10 recommendations."
            )

        scan_result.executive_overview = "\n".join(overview_lines)
        scan_result.ai_summary = f"Security analysis synthesized. Found {len(scan_result.findings)} items across {scan_result.findings_summary.total} audit categories."

        # Framework-specific code injection if missing
        for f in scan_result.findings:
            if not f.remediation_code:
                f.remediation_code = self._default_code_for_category(f)

        return scan_result

    def _default_code_for_category(self, finding: Finding) -> Dict[str, str]:
        code: Dict[str, str] = {}
        fid = finding.id

        if "HSTS" in fid:
            code["nginx"] = "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;"
            code["apache"] = "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'"
            code["express"] = "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));"
            code["django"] = "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True"
        elif "CSP" in fid:
            code["nginx"] = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\" always;"
            code["express"] = "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }));"
            code["django"] = "CSP_DEFAULT_SRC = (\"'self'\",)"
        elif "XFO" in fid:
            code["nginx"] = "add_header X-Frame-Options 'SAMEORIGIN' always;"
            code["apache"] = "Header always append X-Frame-Options 'SAMEORIGIN'"
            code["express"] = "app.use(helmet.frameguard({ action: 'sameorigin' }));"
            code["django"] = "X_FRAME_OPTIONS = 'DENY'"
        elif "XCTO" in fid:
            code["nginx"] = "add_header X-Content-Type-Options 'nosniff' always;"
            code["express"] = "app.use(helmet.noSniff());"
            code["django"] = "SECURE_CONTENT_TYPE_NOSNIFF = True"
        elif "ENV" in fid or "GIT" in fid:
            code["nginx"] = "location ~ /\\.(env|git) {\n    deny all;\n    return 404;\n}"
            code["apache"] = "RedirectMatch 404 /\\.(env|git)"
        elif "SQLI" in fid:
            code["python"] = "# Use Parameterized Queries (Prepared Statements):\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            code["express"] = "// Use Parameterized Queries:\nconst [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);"
            code["django"] = "# Use Django ORM (automatically parameterized):\nUser.objects.filter(id=user_id)"
        elif "XSS" in fid:
            code["express"] = "// Sanitize untrusted input before rendering:\nconst clean = DOMPurify.sanitize(userInput);"
            code["django"] = "# Use Django's template engine default auto-escaping\n# Never mark untrusted inputs with |safe"
            code["fastapi"] = "from markupsafe import escape\nsafe_output = escape(user_input)"
        elif "REDIRECT" in fid:
            code["express"] = "if (!targetUrl.startsWith('/') || targetUrl.startsWith('//')) {\n    return res.redirect('/');\n}"
            code["fastapi"] = "if not target_url.startswith('/') or target_url.startswith('//'):\n    target_url = '/'"
        elif "SECRET" in fid:
            code["general"] = "# Immediately revoke this credential in provider console and store in environment variables:\nAPI_SECRET=your_secret_here"
        elif "SPF" in fid or "DMARC" in fid:
            code["dns"] = "_dmarc.yourdomain.com. IN TXT \"v=DMARC1; p=reject; sp=reject; pct=100;\"\nyourdomain.com. IN TXT \"v=spf1 mx ~all\""
        elif "COOKIE" in fid:
            code["express"] = "res.cookie('token', value, { secure: true, httpOnly: true, sameSite: 'lax' });"
            code["django"] = "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'"
            code["fastapi"] = "response.set_cookie(key='session', value=token, secure=True, httponly=True, samesite='lax')"
        elif "SRI" in fid:
            code["html"] = "<script src=\"https://cdn.example.com/lib.js\"\n  integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n  crossorigin=\"anonymous\"></script>"
        elif "MIXED" in fid:
            code["html"] = "<meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\">"
            code["nginx"] = "add_header Content-Security-Policy \"upgrade-insecure-requests;\" always;"
        elif "GRAPHQL" in fid:
            code["apollo_server"] = "// Apollo Server v4\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production',\n});"
            code["fastapi"] = "# Strawberry / FastAPI\nschema = strawberry.Schema(query=Query, extensions=[NoSchemaIntrospectionCustomRule] if not DEBUG else [])"
        elif "CACHE" in fid:
            code["nginx"] = "location ~* /(api|admin|auth|login) {\n    add_header Cache-Control \"no-store, no-cache, must-revalidate, private\" always;\n    add_header Pragma \"no-cache\" always;\n}"
            code["express"] = "res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');"
            code["fastapi"] = "response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'"
        elif "RATELIMIT" in fid:
            code["nginx"] = "limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\nlocation /api/ {\n    limit_req zone=api_limit burst=20 nodelay;\n}"
            code["express"] = "const rateLimit = require('express-rate-limit');\napp.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));"
            code["fastapi"] = "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\nlimiter = Limiter(key_func=get_remote_address)\n@app.get('/api/resource')\n@limiter.limit('60/minute')\nasync def resource(): ..."
        else:
            code["general"] = "# Review application documentation and apply defense-in-depth principles."

        return code
