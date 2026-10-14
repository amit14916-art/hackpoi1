import re
import uuid
import json
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import httpx

from backend.models import Finding, SeverityLevel


class SensitiveFilesScanner:
    """
    Enterprise-grade sensitive file and directory exposure detector.
    Equipped with a Baseline 404 Canary engine to eliminate false positives on
    Single Page Applications (React, Next.js, Vue) and CDN soft-404 fallbacks.
    Classified under CWE-200, CWE-548, and CWE-552.
    """

    def __init__(self, concurrency: int = 10, timeout: float = 4.0):
        self.timeout = timeout
        self.concurrency = concurrency
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecOpsAudit/2.0",
        }

        # Comprehensive wordlist of high-impact real-world exposed assets
        self.probes = [
            {
                "path": "/.env",
                "name": "Exposed Environment Variables (.env)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["DB_PASSWORD", "SECRET_KEY", "APP_KEY", "AWS_ACCESS_KEY", "DATABASE_URL", "JWT_SECRET", "API_KEY", "REDIS_URL"],
                "syntax_regex": r'^[A-Z0-9_]+\s*=\s*.+$',
                "description": "The application's environment configuration file is publicly accessible. It leaks database credentials, encryption secrets, and API access keys.",
                "impact": "Full database takeover, cloud service compromise, and complete account takeover.",
                "remediation": "Deny all public requests to dotfiles (.*) at the web server / reverse proxy layer.",
                "code": {
                    "nginx": "location ~ /\\.(?!well-known).* { deny all; return 404; }",
                    "apache": "<FilesMatch \"^\\.\">\n  Require all denied\n</FilesMatch>"
                }
            },
            {
                "path": "/.env.local",
                "name": "Exposed Local Environment File (.env.local)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["DB_PASSWORD", "SECRET", "KEY", "TOKEN"],
                "syntax_regex": r'^[A-Z0-9_]+\s*=\s*.+$',
                "description": "Local development environment file exposed on production web root.",
                "impact": "Exposes credentials and local staging API keys.",
                "remediation": "Block access to .env files and add .env* to .gitignore.",
            },
            {
                "path": "/.git/HEAD",
                "name": "Exposed Git Source Code Repository (/.git/HEAD)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["ref: refs/heads/", "ref: refs/"],
                "syntax_regex": r'^(ref:\s*refs/heads/|[0-9a-f]{40})',
                "description": "The .git repository metadata directory is publicly readable. Attackers can dump the entire source code commit history.",
                "impact": "Complete source code leak, proprietary algorithm theft, and discovery of embedded secrets.",
                "remediation": "Block access to the entire /.git directory hierarchy.",
                "code": {
                    "nginx": "location ~ /\\.git { deny all; return 404; }",
                    "apache": "RedirectMatch 404 /\\.git"
                }
            },
            {
                "path": "/.git/config",
                "name": "Exposed Git Repository Configuration (/.git/config)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["[core]", "[remote \"origin\"]"],
                "description": "Git repository configuration file is accessible, exposing internal repository URLs and organization names.",
                "impact": "Exposes internal code repository remotes and developer usernames.",
                "remediation": "Block access to the .git directory.",
            },
            {
                "path": "/docker-compose.yml",
                "name": "Exposed Docker Compose Infrastructure Config",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["services:", "version:"],
                "description": "Exposed docker-compose.yml reveals internal network topology, container names, database passwords, and open ports.",
                "impact": "Provides a blueprint of the internal microservice architecture.",
                "remediation": "Never serve project root directories containing container configurations.",
            },
            {
                "path": "/backup.sql",
                "name": "Exposed Database SQL Dump (backup.sql)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump"],
                "description": "A database backup file is stored directly in the web root and is publicly downloadable.",
                "impact": "Complete exfiltration of all user records, hashed passwords, and private data.",
                "remediation": "Immediately remove all backup files from the public web server directory.",
            },
            {
                "path": "/package.json",
                "name": "Exposed Node.js package.json (Dependency Disclosure)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.LOW,
                "cvss": 3.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe": "CWE-200",
                "owasp": "A06:2021-Vulnerable and Outdated Components",
                "signatures": ["\"dependencies\":", "\"scripts\":"],
                "description": "Node.js package.json is publicly readable, revealing exact npm dependency versions and build scripts.",
                "impact": "Allows attackers to research known CVEs in exact third-party package versions.",
                "remediation": "Configure web server to serve only the compiled dist/ or build/ directory.",
            },
            {
                "path": "/actuator/health",
                "name": "Exposed Spring Boot Actuator Endpoint",
                "category": "Information Disclosure",
                "severity": SeverityLevel.MEDIUM,
                "cvss": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["\"status\":\"UP\"", "{\"status\":"],
                "description": "Spring Boot Actuator diagnostic endpoint is publicly reachable.",
                "impact": "Exposes health and operational status; may lead to heap dumps if actuator/env is exposed.",
                "remediation": "Restrict Spring Actuator endpoints using Spring Security.",
            },
            {
                "path": "/phpinfo.php",
                "name": "Publicly Accessible PHP Info Diagnostic File",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 7.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["PHP Version", "Configuration File (php.ini) Path"],
                "description": "Diagnostic phpinfo() output is exposed, revealing PHP modules, internal paths, and environment settings.",
                "impact": "Facilitates customized exploit generation by pinpointing exact extension versions.",
                "remediation": "Delete diagnostic scripts from production servers.",
            },
            {
                "path": "/.DS_Store",
                "name": "Exposed macOS Directory Metadata (.DS_Store)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.LOW,
                "cvss": 3.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["Bud1", "\x00\x00\x00\x01Bud1"],
                "description": "macOS Finder metadata file is accessible, disclosing hidden filenames and folder layout.",
                "impact": "Information disclosure of hidden file and directory names.",
                "remediation": "Exclude .DS_Store from production deployments and block via web server.",
            },
            {
                "path": "/swagger.json",
                "name": "Public OpenAPI / Swagger Specification",
                "category": "Information Disclosure",
                "severity": SeverityLevel.LOW,
                "cvss": 2.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["\"swagger\":", "\"openapi\":"],
                "description": "Public OpenAPI / Swagger API schema file is exposed, documenting all endpoints and parameters.",
                "impact": "Provides attackers with a full blueprint of API endpoints.",
                "remediation": "Restrict API documentation to authenticated users if APIs are not intended to be public.",
            },
            {
                "path": "/.vscode/sftp.json",
                "name": "Exposed VS Code SFTP Credentials Configuration",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "cwe": "CWE-798",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["\"password\":", "\"privateKeyPath\":", "\"host\":", "\"username\":"],
                "description": "The Visual Studio Code SFTP plugin configuration file is publicly accessible, potentially exposing server IP addresses, usernames, and plaintext SSH/FTP passwords.",
                "impact": "Direct unauthorized SSH or SFTP access into host servers.",
                "remediation": "Block access to the /.vscode directory and ensure it is not deployed to production web roots.",
                "code": {
                    "nginx": "location ~ /\\.vscode { deny all; return 404; }",
                    "apache": "RedirectMatch 404 /\\.vscode"
                }
            },
            {
                "path": "/web.config",
                "name": "Exposed IIS / ASP.NET Configuration (web.config)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["<configuration>", "<system.webServer>", "<connectionStrings>"],
                "description": "Microsoft IIS web.config file is publicly accessible, exposing server routing, authentication configurations, and database connection strings.",
                "impact": "Disclosure of backend architecture, connection strings, and IIS module configurations.",
                "remediation": "Ensure IIS or reverse proxy treats web.config as a protected configuration file and denies read access.",
            },
            {
                "path": "/actuator/env",
                "name": "Exposed Spring Boot Actuator Environment (/actuator/env)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.CRITICAL,
                "cvss": 9.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["\"propertySources\":", "\"activeProfiles\":"],
                "description": "Spring Boot /actuator/env endpoint is publicly exposed without authentication, disclosing system environment variables, JVM properties, and application configurations.",
                "impact": "Full leakage of database passwords, third-party API credentials, and internal host details.",
                "remediation": "Configure Spring Security to restrict or disable the actuator/env endpoint in production.",
            },
            {
                "path": "/.git/index",
                "name": "Exposed Git Repository Index (/.git/index)",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-552",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["DIRC"],
                "description": "Git index file (DIRC binary format) is publicly downloadable, enabling attackers to reconstruct the entire file structure and clone git repository contents.",
                "impact": "Exposes the complete directory hierarchy and enables automated git repository extraction.",
                "remediation": "Deny all access to the /.git directory at the reverse proxy layer.",
            },
            {
                "path": "/phpmyadmin/",
                "name": "Publicly Exposed phpMyAdmin Database Administration",
                "category": "Information Disclosure",
                "severity": SeverityLevel.HIGH,
                "cvss": 7.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "signatures": ["phpMyAdmin", "pma_username", "pma_password"],
                "description": "phpMyAdmin database management panel is publicly accessible over the internet without IP restrictions.",
                "impact": "Exposes database management to brute-force credential stuffing and known phpMyAdmin remote code execution CVEs.",
                "remediation": "Restrict phpMyAdmin to internal VPNs or localhost, or disable it on production hosts.",
            }
        ]

    async def scan(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        semaphore = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False) as client:
            # Step 1: Probe Baseline 404 Canary to fingerprint Soft-404 behavior
            canary_info = await self._probe_404_canary(client, base_url)

            # Step 2: Probe sensitive files
            tasks = [self._probe_item(client, base_url, item, semaphore, canary_info) for item in self.probes]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Finding):
                    findings.append(res)

            # Step 3: Probe robots.txt for hidden paths
            robots_finding = await self._audit_robots(client, base_url)
            if robots_finding:
                findings.append(robots_finding)

            # Step 4: Check for security.txt (RFC 9116)
            security_txt_finding = await self._audit_security_txt(client, base_url)
            if security_txt_finding:
                findings.append(security_txt_finding)

            # Step 5: Check GraphQL Introspection
            graphql_finding = await self._audit_graphql_introspection(client, base_url)
            if graphql_finding:
                findings.append(graphql_finding)

        return findings

    async def _probe_404_canary(self, client: httpx.AsyncClient, base_url: str) -> Dict[str, Any]:
        canary_path = f"/__sec_canary_404_{uuid.uuid4().hex[:12]}__.txt"
        target_endpoint = urljoin(base_url, canary_path)
        try:
            resp = await client.get(target_endpoint, headers=self.headers)
            return {
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", "").lower(),
                "body_length": len(resp.text),
                "is_soft_404": resp.status_code == 200,
            }
        except Exception:
            return {"status_code": 404, "content_type": "", "body_length": 0, "is_soft_404": False}

    async def _probe_item(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        probe: dict,
        semaphore: asyncio.Semaphore,
        canary_info: Dict[str, Any]
    ) -> Optional[Finding]:
        async with semaphore:
            target_endpoint = urljoin(base_url, probe["path"])
            try:
                resp = await client.get(target_endpoint, headers=self.headers)

                # Must be 200 OK
                if resp.status_code != 200:
                    return None

                body = resp.text
                content_type = resp.headers.get("content-type", "").lower()

                # Anti-False-Positive 1: If Canary 404 returned 200, compare body length
                if canary_info.get("is_soft_404"):
                    canary_len = canary_info.get("body_length", 0)
                    if abs(len(body) - canary_len) < 50:
                        # Identical to Soft-404 page
                        return None

                # Anti-False-Positive 2: Non-HTML files must not be HTML documents
                if probe["path"].endswith((".env", ".env.local", ".git/HEAD", ".git/config", ".git/index", ".sql", ".yml", ".DS_Store", "sftp.json", "web.config", "/env")):
                    if "text/html" in content_type and ("<!doctype html>" in body.lower() or "<html" in body.lower()):
                        # Standard HTML SPA or error page returned 200 OK
                        return None

                # Anti-False-Positive 3: Signatures matching
                signatures = probe.get("signatures", [])
                matched_sig = any(sig in body for sig in signatures)

                # Anti-False-Positive 4: Syntax regex validation (for .env or .git/HEAD)
                if probe.get("syntax_regex"):
                    if not re.search(probe["syntax_regex"], body, re.MULTILINE):
                        return None
                elif not matched_sig:
                    return None

                evidence_sample = body[:160].replace("\n", " ").strip()

                return Finding(
                    id=f"SENSITIVE-FILE-{probe['path'].strip('/').replace('/', '-').replace('.', '').upper()}",
                    name=probe["name"],
                    category=probe["category"],
                    severity=probe["severity"],
                    cvss_score=probe["cvss"],
                    cvss_vector=probe.get("cvss_vector"),
                    cwe_id=probe.get("cwe"),
                    owasp_category=probe.get("owasp"),
                    confidence="CERTAIN",
                    endpoint=target_endpoint,
                    description=probe["description"],
                    evidence=f"HTTP 200 OK at {probe['path']}\nContent snippet: {evidence_sample}",
                    request_proof=f"GET {probe['path']} HTTP/1.1\nHost: {urlparse(base_url).netloc}",
                    response_proof=f"HTTP/1.1 200 OK\nContent-Type: {content_type}\n{evidence_sample}...",
                    impact=probe["impact"],
                    remediation_summary=probe["remediation"],
                    remediation_effort="LOW",
                    remediation_code=probe.get("code", {}),
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"]
                )
            except Exception:
                return None

    async def _audit_robots(self, client: httpx.AsyncClient, base_url: str) -> Optional[Finding]:
        target_endpoint = urljoin(base_url, "/robots.txt")
        try:
            resp = await client.get(target_endpoint, headers=self.headers)
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                disallowed_lines = [
                    line.strip() for line in resp.text.splitlines()
                    if line.lower().startswith("disallow:")
                ]
                interesting_keywords = ["admin", "api", "internal", "backup", "secret", "private", "test", "staging", "login"]
                discovered = []
                for line in disallowed_lines:
                    for kw in interesting_keywords:
                        if kw in line.lower() and line not in discovered:
                            discovered.append(line)

                if discovered:
                    return Finding(
                        id="ROBOTS-DISCLOSED-PATHS",
                        name="Sensitive Administrative Paths Disclosed in robots.txt",
                        category="Information Disclosure",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A01:2021-Broken Access Control",
                        confidence="CERTAIN",
                        endpoint=target_endpoint,
                        description="The robots.txt file discloses administrative or private paths to search engine crawlers and prospective attackers.",
                        evidence="Disclosed endpoints:\n" + "\n".join(discovered[:6]),
                        request_proof=f"GET /robots.txt HTTP/1.1\nHost: {urlparse(base_url).netloc}",
                        response_proof=f"HTTP/1.1 200 OK\n" + "\n".join(discovered[:4]),
                        impact="Attackers routinely review robots.txt to discover unlinked admin portals and staging APIs.",
                        remediation_summary="Ensure all disallowed endpoints enforce strict authentication and authorization.",
                        remediation_effort="LOW",
                        references=["https://developers.google.com/search/docs/crawling-indexing/robots/intro"]
                    )
        except Exception:
            pass
        return None

    async def _audit_security_txt(self, client: httpx.AsyncClient, base_url: str) -> Optional[Finding]:
        target_endpoint = urljoin(base_url, "/.well-known/security.txt")
        try:
            resp = await client.get(target_endpoint, headers=self.headers)
            if resp.status_code != 200:
                return Finding(
                    id="INFO-MISSING-SECURITY-TXT",
                    name="Missing RFC 9116 security.txt Policy File",
                    category="Best Practices",
                    severity=SeverityLevel.INFO,
                    cvss_score=1.5,
                    cwe_id="CWE-1059",
                    owasp_category="A05:2021-Security Misconfiguration",
                    confidence="CERTAIN",
                    endpoint=target_endpoint,
                    description="The domain does not publish a security.txt file at /.well-known/security.txt as standardized in RFC 9116. This file provides ethical security researchers with clear instructions and contact channels for responsible vulnerability disclosure.",
                    evidence=f"HTTP status: {resp.status_code} at /.well-known/security.txt",
                    impact="Security researchers may not have an established channel to report vulnerabilities.",
                    remediation_summary="Add a standard /.well-known/security.txt file with your security team's contact email or Bug Bounty link.",
                    remediation_effort="LOW",
                    remediation_code={
                        "security.txt": "Contact: mailto:security@yourdomain.com\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: en\nPolicy: https://yourdomain.com/security-policy"
                    },
                    references=["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"]
                )
        except Exception:
            pass
        return None

    async def _audit_graphql_introspection(self, client: httpx.AsyncClient, base_url: str) -> Optional[Finding]:
        """
        Audits GraphQL endpoints (/graphql, /api/graphql) for public schema introspection (CWE-200).
        """
        introspection_endpoints = ["/graphql", "/api/graphql"]
        query_payload = {"query": "{__schema{types{name}}}"}

        for path in introspection_endpoints:
            target_endpoint = urljoin(base_url, path)
            try:
                resp = await client.post(
                    target_endpoint,
                    json=query_payload,
                    headers={**self.headers, "Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and "data" in data and "__schema" in data.get("data", {}):
                            schema_types = [t.get("name") for t in data["data"]["__schema"].get("types", []) if t.get("name")]
                            sample_types = ", ".join(schema_types[:8]) if schema_types else "Standard introspection types"
                            return Finding(
                                id="VULN-GRAPHQL-INTROSPECTION",
                                name="Publicly Accessible GraphQL Schema Introspection",
                                category="API Security",
                                severity=SeverityLevel.MEDIUM,
                                cvss_score=5.3,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cwe_id="CWE-200",
                                owasp_category="A01:2021-Broken Access Control",
                                confidence="CERTAIN",
                                endpoint=target_endpoint,
                                description=(
                                    "The GraphQL endpoint responds to public schema introspection queries without authentication. "
                                    "This enables prospective attackers to map out the entire GraphQL schema, including internal queries, "
                                    "mutations, types, custom scalar fields, and sensitive relationship graphs."
                                ),
                                evidence=f"Schema introspection enabled at {path}. Sample discovered types: {sample_types}",
                                request_proof=(
                                    f"POST {path} HTTP/1.1\n"
                                    f"Host: {urlparse(base_url).netloc}\n"
                                    f"Content-Type: application/json\n\n"
                                    f"{json.dumps(query_payload)}"
                                ),
                                response_proof=(
                                    f"HTTP/1.1 200 OK\n"
                                    f"Content-Type: {resp.headers.get('content-type', '')}\n\n"
                                    f"{resp.text[:250]}..."
                                ),
                                impact="Full automated reconnaissance of API schema, unlocking rapid discovery of hidden mutations and sensitive fields.",
                                remediation_summary="Disable GraphQL schema introspection in production environments (e.g. introspection: false in Apollo Server or Yoga).",
                                remediation_effort="LOW",
                                remediation_code={
                                    "apollo_server": "// Apollo Server v4\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production',\n});",
                                    "graphql_yoga": "// GraphQL Yoga\nconst yoga = createYoga({\n  schema,\n  graphiql: false,\n  plugins: [useDisableIntrospection()],\n});",
                                    "python_strawberry": "# Strawberry GraphQL\nimport strawberry\nschema = strawberry.Schema(\n    query=Query,\n    extensions=[\n        strawberry.extensions.AddValidationRules([graphql.validation.NoSchemaIntrospectionCustomRule])\n    ] if not DEBUG else []\n)"
                                },
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#introspection",
                                    "https://spec.graphql.org/draft/#sec-Introspection"
                                ]
                            )
                    except Exception:
                        pass
            except Exception:
                pass
        return None
