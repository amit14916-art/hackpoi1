import re
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse
import httpx

from backend.models import Finding, SeverityLevel


class PassiveReconScanner:
    """
    Performs safe, non-intrusive passive reconnaissance against a web application.
    Audits HTTP Security Headers (including modern COOP/COEP/CORP), Information Disclosure banners,
    CORS policies, and Cookie security flags.
    Every finding is mapped to industry-standard CWE IDs and OWASP Top 10 (2021).
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecOpsAudit/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    async def scan(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        base_endpoint = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                response = await client.get(url, headers=self.headers)
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                # 1. Audit HTTP Security Headers
                findings.extend(self._audit_security_headers(resp_headers, base_endpoint, response.status_code))

                # 2. Audit Server / Tech Information Disclosure
                findings.extend(self._audit_info_disclosure(resp_headers, base_endpoint))

                # 3. Audit Cookie Security Flags
                findings.extend(self._audit_cookies(response.headers, base_endpoint))

                # 4. Audit CORS Misconfiguration
                cors_finding = await self._audit_cors(client, url, base_endpoint)
                if cors_finding:
                    findings.append(cors_finding)

                # 5. Audit Subresource Integrity (SRI)
                findings.extend(self._audit_subresource_integrity(response.text, base_endpoint))

                # 6. Audit Mixed Content Over HTTPS
                findings.extend(self._audit_mixed_content(response.text, url, base_endpoint))

                # 7. Audit Cache-Control
                findings.extend(self._audit_cache_control(resp_headers, base_endpoint))

                # 8. Audit Rate Limiting Headers
                findings.extend(self._audit_rate_limiting(resp_headers, base_endpoint))

        except Exception as e:
            findings.append(
                Finding(
                    id="CONN-ERROR",
                    name="Target Connection Warning",
                    category="Connectivity",
                    severity=SeverityLevel.INFO,
                    endpoint=base_endpoint,
                    description=f"Passive recon encountered network anomaly or SSL negotiation issue: {str(e)}",
                    evidence=str(e),
                    impact="Some headers could not be retrieved during the automated probe.",
                    remediation_summary="Ensure the server is publicly reachable on standard HTTP/HTTPS ports.",
                )
            )

        return findings

    def _audit_security_headers(self, headers: Dict[str, str], endpoint: str, status_code: int) -> List[Finding]:
        findings: List[Finding] = []

        # 1. HSTS (Strict-Transport-Security)
        if "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    id="SEC-HDR-HSTS",
                    name="Missing Strict-Transport-Security (HSTS) Header",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server does not enforce HTTPS via the HTTP Strict-Transport-Security header. Browsers may connect over insecure HTTP, leaving users vulnerable to Man-In-The-Middle (MITM) and SSL stripping attacks.",
                    evidence="Strict-Transport-Security header is absent.",
                    request_proof=f"GET / HTTP/1.1\nHost: {urlparse(endpoint).netloc}",
                    response_proof="HTTP/1.1 200 OK\n(Strict-Transport-Security missing)",
                    impact="Attackers on shared networks (Wi-Fi) can intercept credentials and session cookies.",
                    remediation_summary="Configure HSTS with a minimum max-age of 31536000 (1 year) and includeSubDomains.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
                        "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'",
                        "express": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
                        "django": "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True",
                        "fastapi": "from starlette.middleware.base import BaseHTTPMiddleware\n\n@app.middleware('http')\nasync def add_hsts(request, call_next):\n    response = await call_next(request)\n    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'\n    return response",
                    },
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                    ],
                )
            )
        else:
            hsts_val = headers["strict-transport-security"]
            if "max-age" in hsts_val:
                match = re.search(r"max-age=(\d+)", hsts_val)
                if match and int(match.group(1)) < 15768000:
                    findings.append(
                        Finding(
                            id="SEC-HDR-HSTS-LOW",
                            name="Low Max-Age in Strict-Transport-Security",
                            category="Security Headers",
                            severity=SeverityLevel.LOW,
                            cvss_score=3.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-319",
                            owasp_category="A02:2021-Cryptographic Failures",
                            confidence="CERTAIN",
                            endpoint=endpoint,
                            description=f"HSTS max-age is set to {match.group(1)} seconds (< 6 months). OWASP recommends at least 1 year (31536000 seconds).",
                            evidence=f"Strict-Transport-Security: {hsts_val}",
                            impact="Short HSTS duration reduces protection against downgrade attacks for infrequent visitors.",
                            remediation_summary="Increase HSTS max-age to 31536000 seconds (1 year).",
                        )
                    )

        # 2. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    id="SEC-HDR-CSP",
                    name="Missing Content-Security-Policy (CSP)",
                    category="Security Headers",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.2,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="Content-Security-Policy (CSP) header is not defined. CSP is an essential defense-in-depth barrier against Cross-Site Scripting (XSS), malicious script injection, and clickjacking.",
                    evidence="Content-Security-Policy header is absent.",
                    request_proof=f"GET / HTTP/1.1\nHost: {urlparse(endpoint).netloc}",
                    response_proof="HTTP/1.1 200 OK\n(Content-Security-Policy missing)",
                    impact="If an XSS vulnerability exists, attackers can execute arbitrary JavaScript in victim browsers without restriction.",
                    remediation_summary="Deploy a robust Content-Security-Policy with default-src 'self' and explicit allowed origins.",
                    remediation_effort="MEDIUM",
                    remediation_code={
                        "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\" always;",
                        "express": "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"], objectSrc: [\"'none'\"], baseUri: [\"'self'\"] } }));",
                        "django": "# Use django-csp:\nCSP_DEFAULT_SRC = (\"'self'\",)\nCSP_SCRIPT_SRC = (\"'self'\",)\nCSP_OBJECT_SRC = (\"'none'\",)",
                    },
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://owasp.org/www-project-secure-headers/#content-security-policy"
                    ],
                )
            )
        else:
            csp_val = headers["content-security-policy"]
            if "'unsafe-inline'" in csp_val or "'unsafe-eval'" in csp_val:
                findings.append(
                    Finding(
                        id="SEC-HDR-CSP-UNSAFE",
                        name="Weak Directives in Content-Security-Policy ('unsafe-inline' / 'unsafe-eval')",
                        category="Security Headers",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        cwe_id="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        confidence="CERTAIN",
                        endpoint=endpoint,
                        description="Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval', weakening XSS mitigation.",
                        evidence=f"Content-Security-Policy: {csp_val[:120]}...",
                        impact="Inline script injection remains possible if untrusted input is reflected in HTML.",
                        remediation_summary="Migrate inline scripts to external bundles or enforce cryptographic nonces.",
                    )
                )
            if "object-src 'none'" not in csp_val and "default-src 'none'" not in csp_val:
                findings.append(
                    Finding(
                        id="SEC-HDR-CSP-OBJECT-SRC",
                        name="Missing object-src 'none' in Content-Security-Policy",
                        category="Security Headers",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        cwe_id="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        confidence="CERTAIN",
                        endpoint=endpoint,
                        description="The CSP does not restrict object-src to 'none', allowing plugin-based elements (<object>, <embed>, <applet>) to be embedded.",
                        evidence=f"Content-Security-Policy: {csp_val[:120]}...",
                        impact="Attackers can inject malicious plugins or exploit Flash/ActiveX legacy vectors.",
                        remediation_summary="Append \"object-src 'none'\" to your Content-Security-Policy.",
                    )
                )

        # 3. X-Frame-Options (Clickjacking)
        has_frame_ancestors = "content-security-policy" in headers and "frame-ancestors" in headers["content-security-policy"]
        if "x-frame-options" not in headers and not has_frame_ancestors:
            findings.append(
                Finding(
                    id="SEC-HDR-XFO",
                    name="Missing X-Frame-Options (Clickjacking Risk)",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server does not specify X-Frame-Options or CSP frame-ancestors. Malicious web pages can embed this website inside an invisible <iframe> to trick authenticated users into executing unwanted actions (Clickjacking).",
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors was detected.",
                    request_proof=f"GET / HTTP/1.1\nHost: {urlparse(endpoint).netloc}",
                    response_proof="HTTP/1.1 200 OK\n(X-Frame-Options missing)",
                    impact="Users can be deceived into clicking hidden buttons, modifying account settings, or initiating transactions.",
                    remediation_summary="Set X-Frame-Options to DENY or SAMEORIGIN.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header X-Frame-Options 'SAMEORIGIN' always;",
                        "apache": "Header always append X-Frame-Options 'SAMEORIGIN'",
                        "express": "app.use(helmet.frameguard({ action: 'sameorigin' }));",
                        "django": "X_FRAME_OPTIONS = 'DENY'",
                    },
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
                    ],
                )
            )

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                Finding(
                    id="SEC-HDR-XCTO",
                    name="Missing X-Content-Type-Options Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="X-Content-Type-Options: nosniff prevents legacy browsers from MIME-sniffing response content types away from the declared Content-Type, mitigating script execution via user-uploaded images or text files.",
                    evidence=f"X-Content-Type-Options: {headers.get('x-content-type-options', 'Missing')}",
                    impact="Browser may execute user-uploaded files as HTML or JavaScript if Content-Type is improperly handled.",
                    remediation_summary="Add 'X-Content-Type-Options: nosniff' header to all responses.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header X-Content-Type-Options 'nosniff' always;",
                        "apache": "Header always set X-Content-Type-Options 'nosniff'",
                        "express": "app.use(helmet.noSniff());",
                        "django": "SECURE_CONTENT_TYPE_NOSNIFF = True",
                    },
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )

        # 5. Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append(
                Finding(
                    id="SEC-HDR-REFERRER",
                    name="Missing Referrer-Policy Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-116",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="No Referrer-Policy header specified. Browsers may send full query parameters and URLs (potentially containing session tokens or PII) to external third-party domains when following outgoing links.",
                    evidence="Referrer-Policy header is absent.",
                    impact="Sensitive URL tokens or internal parameters can leak to external third parties.",
                    remediation_summary="Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
                        "express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
                        "django": "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
                    },
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                )
            )

        # 6. Permissions-Policy
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append(
                Finding(
                    id="SEC-HDR-PERM-POLICY",
                    name="Missing Permissions-Policy Header",
                    category="Security Headers",
                    severity=SeverityLevel.INFO,
                    cvss_score=2.0,
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="Permissions-Policy restricts sensitive browser features such as camera, microphone, geolocation, and USB APIs from unauthorized third-party embeds.",
                    evidence="Permissions-Policy header is absent.",
                    impact="Embedded iframes might attempt access to client hardware capabilities if not explicitly restricted.",
                    remediation_summary="Specify explicit permissions policy: 'geolocation=(), camera=(), microphone=()'.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;",
                        "express": "app.use(helmet.permittedCrossDomainPolicies());",
                    },
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                )
            )

        # 7. Modern Isolation: Cross-Origin-Opener-Policy (COOP)
        if "cross-origin-opener-policy" not in headers:
            findings.append(
                Finding(
                    id="SEC-HDR-COOP",
                    name="Missing Cross-Origin-Opener-Policy (COOP) Header",
                    category="Security Headers",
                    severity=SeverityLevel.INFO,
                    cvss_score=2.5,
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server does not send Cross-Origin-Opener-Policy. Setting COOP to 'same-origin' isolates the top-level browsing context from cross-origin popups, mitigating Spectre-class side-channel attacks and window.opener hijacking.",
                    evidence="Cross-Origin-Opener-Policy header is absent.",
                    impact="Other websites opened in popups can potentially access the window object.",
                    remediation_summary="Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing contexts.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header Cross-Origin-Opener-Policy 'same-origin' always;",
                        "express": "app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));"
                    }
                )
            )

        return findings

    def _audit_info_disclosure(self, headers: Dict[str, str], endpoint: str) -> List[Finding]:
        findings: List[Finding] = []

        # Server banner
        server_val = headers.get("server", "")
        if server_val and any(char.isdigit() for char in server_val):
            findings.append(
                Finding(
                    id="INFO-SERVER-VERSION",
                    name="Detailed Server Banner Disclosure",
                    category="Information Disclosure",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description=f"The server advertises its software brand and precise version: '{server_val}'. Attackers use exact version strings to look up public CVE exploits and unpatched vulnerabilities.",
                    evidence=f"Server: {server_val}",
                    request_proof=f"GET / HTTP/1.1\nHost: {urlparse(endpoint).netloc}",
                    response_proof=f"HTTP/1.1 200 OK\nServer: {server_val}",
                    impact="Simplifies automated reconnaissance and reconnaissance-driven targeting.",
                    remediation_summary="Strip server banner or suppress version numbers.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "server_tokens off; # in http block",
                        "apache": "ServerTokens Prod\nServerSignature Off",
                        "express": "app.disable('x-powered-by');",
                    },
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                )
            )

        # X-Powered-By
        if "x-powered-by" in headers:
            powered_val = headers["x-powered-by"]
            findings.append(
                Finding(
                    id="INFO-X-POWERED-BY",
                    name="Technology Stack Disclosure (X-Powered-By)",
                    category="Information Disclosure",
                    severity=SeverityLevel.LOW,
                    cvss_score=2.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description=f"Server exposes internal backend framework via 'X-Powered-By: {powered_val}'.",
                    evidence=f"X-Powered-By: {powered_val}",
                    request_proof=f"GET / HTTP/1.1\nHost: {urlparse(endpoint).netloc}",
                    response_proof=f"HTTP/1.1 200 OK\nX-Powered-By: {powered_val}",
                    impact="Discloses framework internals (PHP, ASP.NET, Express), aiding tailored exploit payloads.",
                    remediation_summary="Disable X-Powered-By header in application configuration.",
                    remediation_effort="LOW",
                    remediation_code={
                        "express": "app.disable('x-powered-by');",
                        "php": "; In php.ini\nexpose_php = Off",
                        "nginx": "proxy_hide_header X-Powered-By;",
                    },
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage_Cheat_Sheet.html"],
                )
            )

        return findings

    def _audit_cookies(self, raw_headers: httpx.Headers, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        set_cookie_headers = raw_headers.get_list("set-cookie")

        for cookie_str in set_cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0]
            cookie_name = name_val.split("=")[0] if "=" in name_val else name_val
            lower_parts = [p.lower() for p in parts]

            is_secure = "secure" in lower_parts
            is_httponly = "httponly" in lower_parts
            has_samesite = any(p.startswith("samesite") for p in lower_parts)

            if not is_secure and (endpoint.startswith("https") or "localhost" in endpoint or "127.0.0.1" in endpoint):
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-SECURE-{cookie_name}",
                        name=f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                        category="Cookie Security",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=4.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        confidence="CERTAIN",
                        endpoint=endpoint,
                        description=f"The cookie '{cookie_name}' is set without the 'Secure' attribute. Browsers may transmit this cookie over cleartext HTTP if a user triggers an unencrypted link.",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                        impact="Session cookies can be sniffed on unencrypted Wi-Fi networks.",
                        remediation_summary="Append '; Secure' to all Set-Cookie directives on HTTPS websites.",
                        remediation_effort="LOW",
                        remediation_code={
                            "express": "res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'lax' });",
                            "django": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True",
                            "fastapi": "response.set_cookie(key='session', value=token, secure=True, httponly=True, samesite='lax')",
                        },
                    )
                )

            if not is_httponly:
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-HTTPONLY-{cookie_name}",
                        name=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        category="Cookie Security",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        confidence="CERTAIN",
                        endpoint=endpoint,
                        description=f"The cookie '{cookie_name}' lacks the 'HttpOnly' attribute, making it accessible to client-side scripts via document.cookie.",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                        impact="If Cross-Site Scripting (XSS) occurs, attackers can read this cookie directly.",
                        remediation_summary="Add '; HttpOnly' to all sensitive/session cookie directives.",
                        remediation_effort="LOW",
                        remediation_code={
                            "express": "res.cookie('session', token, { httpOnly: true, secure: true });",
                            "django": "SESSION_COOKIE_HTTPONLY = True",
                        },
                    )
                )

            if not has_samesite:
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-SAMESITE-{cookie_name}",
                        name=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                        category="Cookie Security",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        confidence="CERTAIN",
                        endpoint=endpoint,
                        description=f"The cookie '{cookie_name}' does not declare an explicit SameSite policy (Strict or Lax), increasing vulnerability to Cross-Site Request Forgery (CSRF).",
                        evidence=f"Set-Cookie: {cookie_str[:80]}...",
                        impact="Cross-site requests may automatically include session credentials.",
                        remediation_summary="Configure SameSite=Lax or SameSite=Strict.",
                        remediation_effort="LOW",
                        remediation_code={
                            "express": "res.cookie('name', 'value', { sameSite: 'lax' });",
                            "django": "SESSION_COOKIE_SAMESITE = 'Lax'",
                        },
                    )
                )

        return findings

    async def _audit_cors(self, client: httpx.AsyncClient, target_url: str, endpoint: str) -> Optional[Finding]:
        try:
            evil_origin = "https://evil-attacker.example.com"
            cors_headers = {**self.headers, "Origin": evil_origin}
            resp = await client.options(target_url, headers=cors_headers)

            allow_origin = resp.headers.get("access-control-allow-origin", "")
            allow_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if allow_origin == evil_origin and allow_creds:
                return Finding(
                    id="CORS-ARBITRARY-ORIGIN-CREDS",
                    name="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                    category="CORS Misconfiguration",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                    cwe_id="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server reflects arbitrary untrusted Origins in 'Access-Control-Allow-Origin' while enabling 'Access-Control-Allow-Credentials: true'. This allows external malicious sites to perform authenticated cross-origin reads of victim data.",
                    evidence=f"Origin sent: {evil_origin}\nAccess-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
                    request_proof=f"OPTIONS {target_url} HTTP/1.1\nOrigin: {evil_origin}",
                    response_proof=f"HTTP/1.1 {resp.status_code}\nAccess-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
                    impact="Malicious third-party sites can read private user profiles, transaction history, and sensitive API payloads.",
                    remediation_summary="Whitelist only trusted, explicit domain names and never blindly reflect requested Origin with credentials enabled.",
                    remediation_effort="LOW",
                    remediation_code={
                        "fastapi": "from fastapi.middleware.cors import CORSMiddleware\n\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=['https://app.yourcompany.com'],\n    allow_credentials=True,\n    allow_methods=['GET', 'POST'],\n    allow_headers=['*'],\n)",
                        "express": "const cors = require('cors');\napp.use(cors({ origin: ['https://app.yourcompany.com'], credentials: true }));",
                    },
                    references=["https://portswigger.net/web-security/cors"],
                )
            elif allow_origin == "*":
                return Finding(
                    id="CORS-WILDCARD-ORIGIN",
                    name="CORS Wildcard Access-Control-Allow-Origin (*)",
                    category="CORS Misconfiguration",
                    severity=SeverityLevel.INFO,
                    cvss_score=2.0,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server returns 'Access-Control-Allow-Origin: *'. While normal for public unauthenticated APIs, ensure private or sensitive endpoints are not exposed to wildcard origin requests.",
                    evidence="Access-Control-Allow-Origin: *",
                    impact="Any public domain can make cross-origin requests to this endpoint.",
                    remediation_summary="Restrict wildcard CORS on private or administrative endpoints.",
                    remediation_effort="LOW",
                )
        except Exception:
            pass
        return None

    def _audit_subresource_integrity(self, html: str, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        if not html:
            return findings

        # Find external script tags: <script ... src="https://cdn..." ...>
        parsed_ep = urlparse(endpoint)
        base_host = parsed_ep.netloc.lower()

        script_tags = re.findall(r'<script\b[^>]*>', html, re.IGNORECASE)
        unprotected_scripts = []

        for tag in script_tags:
            src_m = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if src_m:
                src = src_m.group(1).strip()
                # If script is from an external domain
                if src.startswith("//") or src.startswith("http://") or src.startswith("https://"):
                    script_host = urlparse(src if not src.startswith("//") else f"https:{src}").netloc.lower()
                    if script_host and script_host != base_host:
                        # Check for integrity attribute
                        if "integrity=" not in tag.lower():
                            unprotected_scripts.append(src[:80])

        if unprotected_scripts:
            sample_list = "\n".join(f"- {s}" for s in unprotected_scripts[:4])
            findings.append(
                Finding(
                    id="SEC-SRI-MISSING",
                    name="Missing Subresource Integrity (SRI) on Third-Party Scripts",
                    category="Client-Side Security",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-353",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description=f"The application loads {len(unprotected_scripts)} third-party JavaScript asset(s) without Subresource Integrity (SRI) hashes. If the external CDN or hosting provider is compromised, malicious code can be injected directly into your users' sessions.",
                    evidence=f"Scripts without integrity attribute:\n{sample_list}",
                    impact="Supply chain compromise: attackers tampering with the third-party CDN can execute arbitrary JavaScript in victim browsers (Magecart-style attacks).",
                    remediation_summary="Add integrity='sha384-...' and crossorigin='anonymous' attributes to all external third-party script tags.",
                    remediation_effort="LOW",
                    remediation_code={
                        "html": '<script src="https://cdn.example.com/library.js"\n        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n        crossorigin="anonymous"></script>'
                    },
                    references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
                )
            )

        return findings

    def _audit_mixed_content(self, html: str, target_url: str, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        if not html or not target_url.startswith("https"):
            return findings

        # Check for unencrypted HTTP subresources embedded on HTTPS page
        insecure_sources = re.findall(r'(?:src|href)=["\'](http://[^"\']+\.(?:js|css|png|jpg|jpeg|gif|svg|woff2?|ico))["\']', html, re.IGNORECASE)
        # Also check insecure iframes or forms
        insecure_frames = re.findall(r'<iframe\b[^>]*\bsrc=["\'](http://[^"\']+)["\']', html, re.IGNORECASE)
        insecure_forms = re.findall(r'<form\b[^>]*\baction=["\'](http://[^"\']+)["\']', html, re.IGNORECASE)

        all_insecure = list(set(insecure_sources + insecure_frames + insecure_forms))

        if all_insecure:
            sample_insecure = "\n".join(f"- {s}" for s in all_insecure[:4])
            findings.append(
                Finding(
                    id="SEC-MIXED-CONTENT",
                    name="Mixed Content Detected Over HTTPS",
                    category="Transport Security",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
                    cwe_id="CWE-311",
                    owasp_category="A02:2021-Cryptographic Failures",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description=f"The HTTPS page embeds {len(all_insecure)} cleartext (HTTP) subresource(s). This degrades transport layer security and allows Man-in-the-Middle (MITM) attackers on local networks to intercept or alter resource contents.",
                    evidence=f"Cleartext HTTP subresources:\n{sample_insecure}",
                    impact="Loss of confidentiality and integrity for embedded resources; modern browsers will block or flag the site with warnings.",
                    remediation_summary="Update all internal and external resource URLs to use HTTPS exclusively.",
                    remediation_effort="LOW",
                    remediation_code={
                        "html": '<!-- Replace cleartext http:// with https:// -->\n<link rel="stylesheet" href="https://example.com/style.css">\n<script src="https://example.com/app.js"></script>'
                    },
                    references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
                )
            )

        return findings

    def _audit_cache_control(self, headers: Dict[str, str], endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        cache_val = headers.get("cache-control", "").lower()

        if not cache_val:
            findings.append(
                Finding(
                    id="SEC-CACHE-CONTROL-MISSING",
                    name="Missing Cache-Control Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-525",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server does not specify a Cache-Control header. Shared proxies, browser disk caches, and public terminal histories may cache web responses containing sensitive data.",
                    evidence="Cache-Control header is absent.",
                    impact="Sensitive user information or session state may be cached locally or on intermediate proxy caches.",
                    remediation_summary="Specify 'Cache-Control: no-store, max-age=0' on sensitive pages or explicit caching directives on static assets.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "add_header Cache-Control 'no-store, no-cache, must-revalidate, max-age=0' always;",
                        "express": "app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });",
                        "fastapi": "@app.middleware('http')\nasync def add_cache_control(request, call_next):\n    response = await call_next(request)\n    response.headers['Cache-Control'] = 'no-store'\n    return response"
                    },
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching"]
                )
            )

        return findings

    def _audit_rate_limiting(self, headers: Dict[str, str], endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        rate_headers = ["ratelimit-limit", "x-ratelimit-limit", "retry-after"]
        has_rate_limit = any(h in headers for h in rate_headers)

        if not has_rate_limit:
            findings.append(
                Finding(
                    id="INFO-RATE-LIMIT-ABSENT",
                    name="No Standard Rate-Limiting Headers Advertised",
                    category="Best Practices",
                    severity=SeverityLevel.INFO,
                    cvss_score=2.0,
                    cwe_id="CWE-770",
                    owasp_category="A04:2021-Insecure Design",
                    confidence="CERTAIN",
                    endpoint=endpoint,
                    description="The server does not advertise standard rate-limiting headers (e.g. RateLimit-Limit or X-RateLimit-Limit). Ensuring robust rate limiting on public APIs mitigates brute-force attacks and resource exhaustion.",
                    evidence="No RateLimit-Limit or X-RateLimit-Limit headers detected.",
                    impact="APIs without rate limiting are susceptible to automated brute-force, scraping, and denial of service attacks.",
                    remediation_summary="Implement rate limiting (e.g., 60 requests per minute per IP) and expose RateLimit headers.",
                    remediation_effort="LOW",
                    remediation_code={
                        "nginx": "limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;\nlimit_req zone=one burst=20 nodelay;",
                        "express": "const rateLimit = require('express-rate-limit');\napp.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));"
                    },
                    references=["https://owasp.org/www-community/attacks/Denial_of_Service"]
                )
            )

        return findings
