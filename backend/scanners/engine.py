import asyncio
import datetime
from urllib.parse import urlparse
from typing import List, Optional, Callable, Dict, Any

from backend.models import (
    Finding,
    ScanResult,
    ScanStatus,
    ScanSummary,
    SeverityLevel,
)
from backend.scanners.passive_recon import PassiveReconScanner
from backend.scanners.ssl_tls_auditor import SSLTLSAuditor
from backend.scanners.sensitive_files import SensitiveFilesScanner
from backend.scanners.crawler import WebCrawler
from backend.scanners.secrets_scanner import SecretsScanner
from backend.scanners.dns_auditor import DNSAuditor
from backend.scanners.active_dast import ActiveDASTScanner
from backend.verification.domain_verifier import DomainVerifier


class ScannerEngine:
    """
    Central orchestrator for the Enterprise Security Audit & DAST platform.
    Executes a multi-phase, ethical testing pipeline:
    1. Attack surface discovery (Crawling endpoints, forms, parameters, and JS bundles).
    2. HTTP security headers, CORS, cookies, and modern isolation policies.
    3. Client-side secret and credential leak inspection in HTML and JS.
    4. SSL/TLS cryptographic health and cipher suite validation.
    5. Anti-false-positive canary-verified sensitive file discovery (.env, .git, dumps).
    6. Domain infrastructure, SPF, and DMARC email spoofing audit.
    7. Verified Active DAST (Safe SQLi boundaries, XSS canary reflection, open redirects).
    """

    def __init__(self, domain_verifier: Optional[DomainVerifier] = None):
        self.verifier = domain_verifier or DomainVerifier()
        self.crawler = WebCrawler(max_depth=2, max_pages=15)
        self.passive_scanner = PassiveReconScanner()
        self.ssl_auditor = SSLTLSAuditor()
        self.sensitive_scanner = SensitiveFilesScanner()
        self.secrets_scanner = SecretsScanner()
        self.dns_auditor = DNSAuditor()
        self.active_dast = ActiveDASTScanner()

    def normalize_url(self, raw_url: str) -> str:
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        return url

    def calculate_score_and_grade(self, findings: List[Finding]) -> tuple[int, str]:
        score = 100
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                score -= 25
            elif f.severity == SeverityLevel.HIGH:
                score -= 12
            elif f.severity == SeverityLevel.MEDIUM:
                score -= 6
            elif f.severity == SeverityLevel.LOW:
                score -= 2

        score = max(0, min(100, score))

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def summarize_findings(self, findings: List[Finding]) -> ScanSummary:
        summary = ScanSummary(total=len(findings))
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                summary.critical += 1
            elif f.severity == SeverityLevel.HIGH:
                summary.high += 1
            elif f.severity == SeverityLevel.MEDIUM:
                summary.medium += 1
            elif f.severity == SeverityLevel.LOW:
                summary.low += 1
            elif f.severity == SeverityLevel.INFO:
                summary.info += 1
        return summary

    async def run_scan(
        self,
        scan_id: str,
        raw_url: str,
        scan_type: str = "passive",
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> ScanResult:
        target_url = self.normalize_url(raw_url)
        parsed = urlparse(target_url)
        domain = parsed.hostname or target_url

        is_local = domain in ["localhost", "127.0.0.1", "0.0.0.0"] or domain.endswith(".local")
        is_verified = self.verifier.is_verified(domain) or is_local

        result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            domain=domain,
            status=ScanStatus.SCANNING,
            current_step="Discovering attack surface and endpoints",
            progress=10,
            started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            is_domain_verified=is_verified,
        )

        all_findings: List[Finding] = []

        try:
            # Phase 1: Attack Surface Discovery & Crawling (15%)
            if on_progress:
                on_progress(15, "Crawling application routes, forms, parameters, and scripts")
            result.current_step = "Crawling application routes, forms, parameters, and scripts"
            result.progress = 15

            crawl_data = await self.crawler.crawl(target_url)
            discovered_endpoints = crawl_data.get("endpoints", [])
            js_assets = crawl_data.get("js_assets", [])

            # Phase 2: Security Headers, CORS, Cookies & Modern Isolation (30%)
            if on_progress:
                on_progress(30, "Auditing Security Headers, CORS, & Cookie Security")
            result.current_step = "Auditing Security Headers, CORS, & Cookie Security"
            result.progress = 30

            passive_findings = await self.passive_scanner.scan(target_url)
            all_findings.extend(passive_findings)

            # Phase 3: Client-Side Secrets & Credential Leak Scan (45%)
            if on_progress:
                on_progress(45, "Scanning HTML & JavaScript bundles for hardcoded secrets")
            result.current_step = "Scanning HTML & JavaScript bundles for hardcoded secrets"
            result.progress = 45

            secret_findings = await self.secrets_scanner.scan_assets(target_url, js_assets)
            all_findings.extend(secret_findings)

            # Phase 4: SSL/TLS Cryptographic Analysis (60%)
            if on_progress:
                on_progress(60, "Inspecting SSL/TLS Certificate & Cipher Suites")
            result.current_step = "Inspecting SSL/TLS Certificate & Cipher Suites"
            result.progress = 60

            ssl_findings = await self.ssl_auditor.audit(target_url)
            all_findings.extend(ssl_findings)

            # Phase 5: Anti-False-Positive Canary Sensitive File Probing (75%)
            if on_progress:
                on_progress(75, "Probing sensitive paths (.env, .git, dumps) with Canary 404 verification")
            result.current_step = "Probing sensitive paths (.env, .git, dumps) with Canary 404 verification"
            result.progress = 75

            sensitive_findings = await self.sensitive_scanner.scan(target_url)
            all_findings.extend(sensitive_findings)

            # Phase 6: DNS, SPF & DMARC Email Security (85%)
            if on_progress:
                on_progress(85, "Auditing Domain DNS, SPF, & DMARC anti-spoofing policies")
            result.current_step = "Auditing Domain DNS, SPF, & DMARC anti-spoofing policies"
            result.progress = 85

            dns_findings = await self.dns_auditor.audit(target_url)
            all_findings.extend(dns_findings)

            # Phase 7: Verified Active DAST Testing (SQLi, XSS, Redirects, Methods) (90%)
            if scan_type == "active" or is_local:
                if not is_verified:
                    all_findings.append(
                        Finding(
                            id="LEGAL-GUARDRAIL-ACTIVE-BLOCKED",
                            name="Active DAST Scan Blocked: Domain Ownership Not Verified",
                            category="Legal Guardrail",
                            severity=SeverityLevel.INFO,
                            cvss_score=0.0,
                            endpoint=target_url,
                            description="Intrusive active DAST fuzzing was blocked to comply with cyber laws and anti-abuse policies. To unlock active tests, verify domain ownership via DNS TXT record or HTTP verification challenge.",
                            evidence=f"Verification status for domain '{domain}': UNVERIFIED",
                            impact="Only passive, zero-impact external checks were performed.",
                            remediation_summary="Open Domain Verification in the dashboard to generate and complete a verification challenge.",
                        )
                    )
                else:
                    if on_progress:
                        on_progress(90, "Executing Verified Active DAST Checks (SQLi boundaries, XSS reflection, Redirects)")
                    result.current_step = "Executing Verified Active DAST Checks"
                    result.progress = 90

                    active_findings = await self.active_dast.scan(target_url, discovered_endpoints)
                    all_findings.extend(active_findings)

            # Calculate scores and update result
            score, grade = self.calculate_score_and_grade(all_findings)
            result.score = score
            result.grade = grade
            result.findings = all_findings
            result.findings_summary = self.summarize_findings(all_findings)
            result.status = ScanStatus.ANALYZING_AI
            result.progress = 92
            result.current_step = "Passing findings to AI Remediation Engine"

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error = f"Scanner engine encountered fatal error: {str(e)}"

        return result
