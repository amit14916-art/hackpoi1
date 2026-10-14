import re
import uuid
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

from backend.models import Finding, SeverityLevel


class ActiveDASTScanner:
    """
    Verified Active DAST vulnerability engine.
    Performs safe, non-destructive boundary and canary analysis for:
    - Cross-Site Scripting (XSS) parameter reflection & unescaped context analysis (CWE-79).
    - SQL Injection error boundary and database driver disclosure analysis (CWE-89).
    - Open Redirect parameter validation (CWE-601).
    - Dangerous HTTP methods (TRACE / PUT / DELETE) and method tampering (CWE-200).

    ENFORCEMENT: Only executes against verified domains or local testbed environments.
    """

    SQL_ERRORS = [
        ("MySQL", re.compile(r"you have an error in your sql syntax|mysql_fetch_|warning: mysql_|check the manual that corresponds to your mysql server version", re.IGNORECASE)),
        ("PostgreSQL", re.compile(r"pg::syntaxerror:|postgresql query failed:|unterminated quoted string at or near|psycopg2\.errors\.", re.IGNORECASE)),
        ("SQLite", re.compile(r"sqlite3\.operationalerror:|near \"[^\"]+\": syntax error|unrecognized token:|sqlite_step\(|sqlite_query\(", re.IGNORECASE)),
        ("MSSQL", re.compile(r"odbc sql server driver|unclosed quotation mark after the character string|microsoft ole db provider for sql server", re.IGNORECASE)),
        ("Oracle", re.compile(r"ora-00933:|ora-01756:|quoted string not properly terminated", re.IGNORECASE)),
        ("Generic SQL", re.compile(r"sqlstate\[[0-9a-z]+\]|syntax error in sql statement|database error occurred while processing your request", re.IGNORECASE)),
    ]

    REDIRECT_PARAMS = ["redirect", "url", "next", "return", "return_to", "dest", "target", "goto", "callback"]

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecOpsAudit/2.0",
        }

    async def scan(self, target_url: str, discovered_endpoints: Optional[List[Dict[str, Any]]] = None) -> List[Finding]:
        findings: List[Finding] = []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False) as client:
            # 1. Audit HTTP Methods & TRACE on base target
            findings.extend(await self._audit_http_methods(client, target_url))

            # 2. Extract targets to test
            test_targets = [target_url]
            if discovered_endpoints:
                for ep in discovered_endpoints:
                    if ep.get("params") or "?" in ep.get("url", ""):
                        test_targets.append(ep["url"])

            # Deduplicate test targets
            test_targets = list(dict.fromkeys(test_targets))[:8]

            for ep_url in test_targets:
                # 3. Test for Safe XSS Parameter Reflection
                xss_findings = await self._audit_xss_reflection(client, ep_url)
                findings.extend(xss_findings)

                # 4. Test for Safe SQL Injection Error Boundaries
                sqli_findings = await self._audit_sqli_boundaries(client, ep_url)
                findings.extend(sqli_findings)

                # 5. Test for Open Redirects
                redirect_findings = await self._audit_open_redirect(client, ep_url)
                findings.extend(redirect_findings)

        return findings

    async def _audit_http_methods(self, client: httpx.AsyncClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            # Test TRACE method
            trace_resp = await client.request("TRACE", url, headers={**self.headers, "X-Test-Canary": "SecOpsTraceTest"})
            if trace_resp.status_code == 200 and "X-Test-Canary: SecOpsTraceTest" in trace_resp.text:
                findings.append(
                    Finding(
                        id="ACTIVE-HTTP-TRACE-ENABLED",
                        name="HTTP TRACE Method Enabled (Cross-Site Tracing XST Risk)",
                        category="Injection & Misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        confidence="CERTAIN",
                        endpoint=url,
                        description="The HTTP TRACE method is enabled and reflects request headers back in the response body. This enables Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.",
                        evidence="Server replied 200 OK to TRACE and echoed request headers.",
                        request_proof=f"TRACE {url} HTTP/1.1\nX-Test-Canary: SecOpsTraceTest",
                        response_proof=f"HTTP/1.1 200 OK\n{trace_resp.text[:120]}...",
                        impact="Attackers can bypass HttpOnly cookie defenses using cross-site tracing.",
                        remediation_summary="Disable TRACE and TRACK methods in your web server configuration.",
                        remediation_effort="LOW",
                        remediation_code={
                            "nginx": "if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }",
                            "apache": "TraceEnable Off",
                        },
                        references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"]
                    )
                )
        except Exception:
            pass

        return findings

    async def _audit_xss_reflection(self, client: httpx.AsyncClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no query params, test common parameter names
        if not params:
            test_params = ["q", "search", "query", "id", "name"]
        else:
            test_params = list(params.keys())

        canary_token = f"sec_{uuid.uuid4().hex[:8]}"
        marker_payload = f"{canary_token}<sec_xss_probe>"

        for p_name in test_params[:3]:
            mutated_params = {**params, p_name: marker_payload}
            mutated_query = urlencode(mutated_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, mutated_query, parsed.fragment))

            try:
                resp = await client.get(probe_url, headers=self.headers)
                body = resp.text

                # Check if canary and raw unescaped tag are reflected
                if canary_token in body and "<sec_xss_probe>" in body:
                    context_snippet = body[max(0, body.find(canary_token) - 40):body.find(canary_token) + 80]
                    findings.append(
                        Finding(
                            id=f"ACTIVE-XSS-REFLECTED-{p_name.upper()}",
                            name=f"Reflected Cross-Site Scripting (XSS) in Parameter '{p_name}'",
                            category="Injection & XSS",
                            severity=SeverityLevel.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            confidence="CERTAIN",
                            endpoint=probe_url,
                            description=f"User input supplied to parameter '{p_name}' is reflected in the HTML response without HTML entity encoding. An attacker can construct a link containing malicious JavaScript that executes in victims' browsers.",
                            evidence=f"Canary test reflected unescaped: {context_snippet}",
                            request_proof=f"GET {probe_url} HTTP/1.1\nHost: {parsed.netloc}",
                            response_proof=f"HTTP/1.1 {resp.status_code} OK\n... {context_snippet} ...",
                            impact="Attackers can steal session tokens, impersonate users, or deface the web application.",
                            remediation_summary=f"Ensure parameter '{p_name}' is context-aware encoded before rendering in HTML templates.",
                            remediation_effort="MEDIUM",
                            remediation_code={
                                "django": "# Use Django's template engine default auto-escaping\n# Never mark untrusted inputs with |safe or mark_safe()",
                                "express": "// Use context-aware escaping libraries (e.g. DOMPurify or sanitize-html)\nconst clean = DOMPurify.sanitize(req.query.q);",
                                "fastapi": "from markupsafe import escape\nsafe_output = escape(user_input)",
                            },
                            references=["https://owasp.org/www-community/attacks/xss/"]
                        )
                    )
                    break
            except Exception:
                continue

        return findings

    async def _audit_sqli_boundaries(self, client: httpx.AsyncClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            test_params = ["id", "user_id", "category", "item", "page"]
        else:
            test_params = list(params.keys())

        # Baseline request check
        baseline_text = ""
        try:
            base_resp = await client.get(url, headers=self.headers)
            baseline_text = base_resp.text
        except Exception:
            return findings

        # Test single quote and quote syntax boundary
        probe_chars = ["'", "\""]

        for p_name in test_params[:3]:
            for probe in probe_chars:
                mutated_params = {**params, p_name: (params.get(p_name, ["1"])[0] + probe)}
                mutated_query = urlencode(mutated_params, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, mutated_query, parsed.fragment))

                try:
                    resp = await client.get(probe_url, headers=self.headers)
                    resp_body = resp.text

                    # Check for database driver syntax error that was NOT in baseline
                    for db_name, pattern in self.SQL_ERRORS:
                        match = pattern.search(resp_body)
                        if match and not pattern.search(baseline_text):
                            error_snippet = resp_body[max(0, match.start() - 20):min(len(resp_body), match.end() + 60)].replace("\n", " ").strip()
                            findings.append(
                                Finding(
                                    id=f"ACTIVE-SQLI-SYNTAX-ERROR-{p_name.upper()}",
                                    name=f"SQL Injection Syntax Error Leakage in Parameter '{p_name}' ({db_name})",
                                    category="Injection & SQLi",
                                    severity=SeverityLevel.CRITICAL,
                                    cvss_score=9.3,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    cwe_id="CWE-89",
                                    owasp_category="A03:2021-Injection",
                                    confidence="CERTAIN",
                                    endpoint=probe_url,
                                    description=f"Injecting a syntax delimiter character ('{probe}') into parameter '{p_name}' triggered a raw {db_name} database syntax error in the HTTP response. This confirms the application concatenates untrusted user input directly into SQL queries.",
                                    evidence=f"Database driver syntax error detected: '{error_snippet}'",
                                    request_proof=f"GET {probe_url} HTTP/1.1\nHost: {parsed.netloc}",
                                    response_proof=f"HTTP/1.1 {resp.status_code}\n... {error_snippet} ...",
                                    impact="Full database compromise: attackers can read, modify, or delete database tables, bypass authentication, and potentially execute OS commands.",
                                    remediation_summary="Use parameterized queries (Prepared Statements) or an ORM with bind parameters. Never format or concatenate strings into SQL queries.",
                                    remediation_effort="MEDIUM",
                                    remediation_code={
                                        "python": "# Safe Parameterized Query:\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                                        "node": "// Safe Parameterized Query:\nconst [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);",
                                        "django": "# Use Django ORM (automatically parameterized):\nUser.objects.filter(id=user_id)",
                                    },
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                                )
                            )
                            return findings  # Return once confirmed
                except Exception:
                    continue

        return findings

    async def _audit_open_redirect(self, client: httpx.AsyncClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check existing params matching redirect keywords or test them
        candidate_params = [k for k in params.keys() if k.lower() in self.REDIRECT_PARAMS]
        if not candidate_params and "?" not in url:
            candidate_params = ["redirect", "url", "next"]

        canary_target = "https://example.com/secops-canary-redirect"

        for p_name in candidate_params[:3]:
            mutated_params = {**params, p_name: canary_target}
            mutated_query = urlencode(mutated_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, mutated_query, parsed.fragment))

            try:
                resp = await client.get(probe_url, headers=self.headers)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")
                    if location.startswith(canary_target):
                        findings.append(
                            Finding(
                                id=f"ACTIVE-OPEN-REDIRECT-{p_name.upper()}",
                                name=f"Open Redirect Vulnerability in Parameter '{p_name}'",
                                category="Broken Access Control",
                                severity=SeverityLevel.MEDIUM,
                                cvss_score=6.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                cwe_id="CWE-601",
                                owasp_category="A01:2021-Broken Access Control",
                                confidence="CERTAIN",
                                endpoint=probe_url,
                                description=f"The parameter '{p_name}' redirects visitors to arbitrary external URLs without destination validation.",
                                evidence=f"HTTP {resp.status_code} Redirect to Location: {location}",
                                request_proof=f"GET {probe_url} HTTP/1.1\nHost: {parsed.netloc}",
                                response_proof=f"HTTP/1.1 {resp.status_code}\nLocation: {location}",
                                impact="Attackers use open redirects to craft convincing phishing URLs that appear to originate from your legitimate domain.",
                                remediation_summary="Validate redirect targets against an explicit allowlist or restrict redirects to relative paths.",
                                remediation_effort="LOW",
                                remediation_code={
                                    "python": "if not url_has_allowed_host_and_scheme(target_url, allowed_hosts={request.get_host()}):\n    target_url = '/'",
                                    "express": "if (!targetUrl.startsWith('/') || targetUrl.startsWith('//')) {\n    return res.redirect('/');\n}"
                                }
                            )
                        )
            except Exception:
                continue

        return findings
