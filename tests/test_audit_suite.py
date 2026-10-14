import asyncio
import pytest
from backend.models import Finding, SeverityLevel, ScanResult, ScanStatus, VerificationMethod
from backend.scanners.engine import ScannerEngine
from backend.scanners.crawler import WebCrawler
from backend.scanners.secrets_scanner import SecretsScanner
from backend.scanners.sensitive_files import SensitiveFilesScanner
from backend.scanners.active_dast import ActiveDASTScanner
from backend.verification.domain_verifier import DomainVerifier
from backend.reporting.report_generator import ReportGenerator
from backend.ai.remediation_engine import AIRemediationEngine


def test_scoring_and_grades():
    engine = ScannerEngine()
    
    # 0 findings -> 100 A+
    score, grade = engine.calculate_score_and_grade([])
    assert score == 100
    assert grade == "A+"

    # 1 Critical (-25) -> 75 B
    crit_finding = Finding(
        id="TEST-CRIT",
        name="Critical Leak",
        category="Information Disclosure",
        severity=SeverityLevel.CRITICAL,
        endpoint="http://example.com",
        description="Test desc",
    )
    score, grade = engine.calculate_score_and_grade([crit_finding])
    assert score == 75
    assert grade == "B"

    # 4 Criticals (-100) -> 0 F
    score, grade = engine.calculate_score_and_grade([crit_finding] * 4)
    assert score == 0
    assert grade == "F"


def test_domain_verification_challenge_generation():
    verifier = DomainVerifier()
    challenge = verifier.create_challenge("https://example.com:8080/path")
    
    assert challenge.domain == "example.com"
    assert challenge.token is not None
    assert challenge.dns_record_name == "_sec-verify.example.com"
    assert "sec-verify=" in challenge.dns_record_value
    assert challenge.http_file_path == "/.well-known/security-check.txt"


def test_secrets_scanner_patterns():
    scanner = SecretsScanner()
    
    # Test Google API Key detection
    test_content = "const config = { apiKey: 'AIzaSyD-mockGoogleFirebaseKey123456' };"
    findings = scanner._analyze_content(test_content, "https://test.local/bundle.js")
    assert len(findings) == 1
    assert findings[0].id.startswith("SECRET-GOOGLE-API-KEY")
    assert findings[0].cwe_id == "CWE-798"
    assert findings[0].owasp_category == "A07:2021-Identification and Authentication Failures"

    # Test AWS Access Key detection
    aws_content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings_aws = scanner._analyze_content(aws_content, "https://test.local/config.js")
    assert len(findings_aws) == 1
    assert findings_aws[0].id.startswith("SECRET-AWS-ACCESS-KEY")
    assert findings_aws[0].severity == SeverityLevel.CRITICAL


def test_active_dast_sqli_error_signatures():
    scanner = ActiveDASTScanner()
    # Check MySQL error signature match
    sample_mysql = "check the manual that corresponds to your MySQL server version for the right syntax to use"
    matched = False
    for db_name, pattern in scanner.SQL_ERRORS:
        if pattern.search(sample_mysql):
            matched = True
            assert db_name == "MySQL"
            break
    assert matched is True

    # Check SQLite error signature match
    sample_sqlite = "sqlite3.OperationalError: near \"'\": syntax error in SELECT * FROM products"
    matched_sqlite = False
    for db_name, pattern in scanner.SQL_ERRORS:
        if pattern.search(sample_sqlite):
            matched_sqlite = True
            assert db_name == "SQLite"
            break
    assert matched_sqlite is True


def test_report_generation_with_cwe_and_proofs():
    result = ScanResult(
        scan_id="test_scan_001",
        target_url="https://test.local",
        domain="test.local",
        status=ScanStatus.COMPLETED,
        started_at="2026-09-20T12:00:00Z",
        score=70,
        grade="B",
        findings=[
            Finding(
                id="ACTIVE-SQLI-TEST",
                name="SQL Injection in Parameter 'id'",
                category="Injection & SQLi",
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                confidence="CERTAIN",
                endpoint="https://test.local/api/products?id=1'",
                description="Raw database syntax error reflected.",
                request_proof="GET /api/products?id=1' HTTP/1.1",
                response_proof="HTTP/1.1 500 Internal Server Error\nsqlite3.OperationalError: syntax error",
                remediation_summary="Use Parameterized Queries.",
                remediation_code={"python": "cursor.execute('SELECT * FROM users WHERE id = %s', (id,))"}
            )
        ]
    )
    
    # Markdown output verification
    md = ReportGenerator.to_markdown(result)
    assert "# Automated Web Security Audit Report" in md
    assert "**CWE:** CWE-89" in md
    assert "**OWASP Top 10:** A03:2021-Injection" in md
    assert "Request Proof:" in md
    assert "Response Proof:" in md

    # HTML output verification
    html = ReportGenerator.to_printable_html(result)
    assert "<!DOCTYPE html>" in html
    assert "CWE-89" in html
    assert "A03:2021-Injection" in html
    assert "Technical Request & Response Proof" in html


@pytest.mark.asyncio
async def test_ai_remediation_heuristics_with_cwe():
    ai = AIRemediationEngine()
    result = ScanResult(
        scan_id="test_scan_002",
        target_url="https://test.local",
        domain="test.local",
        status=ScanStatus.ANALYZING_AI,
        started_at="2026-09-20T12:00:00Z",
        findings=[
            Finding(
                id="ACTIVE-SQLI-TEST",
                name="SQL Injection in Parameter 'id'",
                category="Injection & SQLi",
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.3,
                cwe_id="CWE-89",
                endpoint="https://test.local/api/products?id=1'",
                description="SQLi detected",
            )
        ]
    )
    result.findings_summary = ScannerEngine().summarize_findings(result.findings)
    
    enriched = await ai.analyze_and_enrich(result, framework_hint="python")
    assert enriched.executive_overview is not None
    assert "Executive Security Assessment" in enriched.executive_overview
    assert "python" in enriched.findings[0].remediation_code
    assert "Parameterized Queries" in enriched.findings[0].remediation_code["python"]


def test_passive_recon_sri_audit():
    from backend.scanners.passive_recon import PassiveReconScanner
    scanner = PassiveReconScanner()

    # Unprotected external script
    html_vuln = '<html><head><script src="https://cdn.example.com/untrusted.js"></script></head></html>'
    findings = scanner._audit_subresource_integrity(html_vuln, "https://target.local")
    assert len(findings) == 1
    assert findings[0].id == "SEC-SRI-MISSING"
    assert findings[0].cwe_id == "CWE-353"
    assert findings[0].owasp_category == "A08:2021-Software and Data Integrity Failures"
    assert "untrusted.js" in findings[0].evidence

    # Protected external script with integrity
    html_safe = '<html><head><script src="https://cdn.example.com/trusted.js" integrity="sha384-xyz" crossorigin="anonymous"></script></head></html>'
    findings_safe = scanner._audit_subresource_integrity(html_safe, "https://target.local")
    assert len(findings_safe) == 0

    # Same-origin script should not flag
    html_local = '<html><head><script src="/static/app.js"></script></head></html>'
    findings_local = scanner._audit_subresource_integrity(html_local, "https://target.local")
    assert len(findings_local) == 0


def test_passive_recon_mixed_content_audit():
    from backend.scanners.passive_recon import PassiveReconScanner
    scanner = PassiveReconScanner()

    # HTTPS target with cleartext HTTP image
    html_mixed = '<html><body><img src="http://insecure-cdn.com/banner.png"><script src="http://insecure-cdn.com/ad.js"></script></body></html>'
    findings = scanner._audit_mixed_content(html_mixed, "https://secure.target.local", "https://secure.target.local")
    assert len(findings) == 1
    assert findings[0].id == "SEC-MIXED-CONTENT"
    assert findings[0].cwe_id == "CWE-311"
    assert findings[0].owasp_category == "A02:2021-Cryptographic Failures"
    assert "http://insecure-cdn.com/banner.png" in findings[0].evidence

    # Non-HTTPS target should not flag mixed content
    findings_http = scanner._audit_mixed_content(html_mixed, "http://plain.target.local", "http://plain.target.local")
    assert len(findings_http) == 0


def test_passive_recon_cache_control_and_rate_limiting():
    from backend.scanners.passive_recon import PassiveReconScanner
    scanner = PassiveReconScanner()

    # Missing Cache-Control
    headers_no_cache = {"content-type": "text/html"}
    findings_cache = scanner._audit_cache_control(headers_no_cache, "https://target.local")
    assert len(findings_cache) == 1
    assert findings_cache[0].id == "SEC-CACHE-CONTROL-MISSING"
    assert findings_cache[0].cwe_id == "CWE-525"

    # Present Cache-Control
    headers_with_cache = {"cache-control": "no-store, private"}
    findings_cache_ok = scanner._audit_cache_control(headers_with_cache, "https://target.local")
    assert len(findings_cache_ok) == 0

    # Missing Rate Limiting
    findings_rl = scanner._audit_rate_limiting({}, "https://target.local")
    assert len(findings_rl) == 1
    assert findings_rl[0].id == "INFO-RATE-LIMIT-ABSENT"
    assert findings_rl[0].cwe_id == "CWE-770"

    # Present Rate Limiting
    findings_rl_ok = scanner._audit_rate_limiting({"x-ratelimit-limit": "100"}, "https://target.local")
    assert len(findings_rl_ok) == 0


def test_sensitive_files_probes_coverage():
    scanner = SensitiveFilesScanner()
    probe_paths = [p["path"] for p in scanner.probes]

    assert "/.vscode/sftp.json" in probe_paths
    assert "/web.config" in probe_paths
    assert "/actuator/env" in probe_paths
    assert "/.git/index" in probe_paths
    assert "/phpmyadmin/" in probe_paths


@pytest.mark.asyncio
async def test_graphql_introspection_finding():
    scanner = SensitiveFilesScanner()
    
    # Verify the finding structure when introspection succeeds
    class MockGraphQLResponse:
        status_code = 200
        headers = {"content-type": "application/json"}
        text = '{"data": {"__schema": {"types": [{"name": "User"}, {"name": "Payment"}]}}}'
        
        def json(self):
            return {
                "data": {
                    "__schema": {
                        "types": [{"name": "User"}, {"name": "Payment"}]
                    }
                }
            }

    class MockClient:
        async def post(self, url, **kwargs):
            return MockGraphQLResponse()

    finding = await scanner._audit_graphql_introspection(MockClient(), "https://target.local")
    assert finding is not None
    assert finding.id == "VULN-GRAPHQL-INTROSPECTION"
    assert finding.cwe_id == "CWE-200"
    assert finding.owasp_category == "A01:2021-Broken Access Control"
    assert "User" in finding.evidence

