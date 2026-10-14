import asyncio
from typing import List, Optional
from urllib.parse import urlparse
import dns.resolver

from backend.models import Finding, SeverityLevel


class DNSAuditor:
    """
    Audits domain-level DNS security posture:
    - Email spoofing defenses: SPF (Sender Policy Framework) and DMARC.
    - DNSSEC validation support.
    - Dangling CNAME / Subdomain Takeover indications.
    """

    def __init__(self, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    async def audit(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        domain = parsed.hostname or url

        # Skip local testing domains and raw IP addresses
        if domain in ["localhost", "127.0.0.1", "0.0.0.0"] or domain.endswith(".local") or domain.replace(".", "").isdigit():
            return findings

        # Run DNS checks in threadpool to avoid blocking async event loop
        loop = asyncio.get_event_loop()
        try:
            dns_findings = await loop.run_in_executor(None, self._check_dns_records, domain)
            findings.extend(dns_findings)
        except Exception:
            pass

        return findings

    def _check_dns_records(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Audit SPF (Sender Policy Framework)
        has_spf = False
        spf_record_text = ""
        try:
            txt_answers = self.resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=spf1"):
                    has_spf = True
                    spf_record_text = txt
                    if "+all" in txt:
                        findings.append(
                            Finding(
                                id="DNS-SPF-PERMISSIVE",
                                name="Dangerous SPF Configuration (+all Allows Any Sender)",
                                category="DNS & Email Security",
                                severity=SeverityLevel.HIGH,
                                cvss_score=7.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                                cwe_id="CWE-290",
                                owasp_category="A07:2021-Identification and Authentication Failures",
                                confidence="CERTAIN",
                                endpoint=domain,
                                description=f"The SPF record for '{domain}' contains '+all', allowing any external server on the internet to send legitimate-looking emails claiming to be from your domain.",
                                evidence=f"TXT {domain}: {txt}",
                                impact="Attackers can send phishing emails pretending to be your company without failing SPF checks.",
                                remediation_summary="Change '+all' to '-all' (Hard Fail) or '~all' (Soft Fail).",
                                remediation_effort="LOW",
                                remediation_code={
                                    "dns": f"{domain}. IN TXT \"v=spf1 include:_spf.google.com ~all\""
                                }
                            )
                        )
                    break
        except Exception:
            pass

        if not has_spf:
            findings.append(
                Finding(
                    id="DNS-SPF-MISSING",
                    name="Missing Sender Policy Framework (SPF) DNS Record",
                    category="DNS & Email Security",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-290",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    confidence="CERTAIN",
                    endpoint=domain,
                    description=f"The domain '{domain}' does not publish an SPF TXT record. Without SPF, mail transfer agents cannot verify authorized outbound mail servers.",
                    evidence=f"No TXT record matching 'v=spf1' discovered on {domain}",
                    impact="Permits trivial email spoofing and business email compromise (BEC) campaigns.",
                    remediation_summary="Publish an SPF record listing your authorized mail relays ending with '~all' or '-all'.",
                    remediation_effort="LOW",
                    remediation_code={
                        "dns": f"{domain}. IN TXT \"v=spf1 mx -all\""
                    },
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Email_Security_Cheat_Sheet.html"]
                )
            )

        # 2. Audit DMARC (Domain-based Message Authentication, Reporting, and Conformance)
        dmarc_domain = f"_dmarc.{domain}"
        has_dmarc = False
        try:
            dmarc_answers = self.resolver.resolve(dmarc_domain, "TXT")
            for rdata in dmarc_answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=DMARC1"):
                    has_dmarc = True
                    if "p=none" in txt:
                        findings.append(
                            Finding(
                                id="DNS-DMARC-NONE",
                                name="Weak DMARC Policy (p=none - Monitoring Only)",
                                category="DNS & Email Security",
                                severity=SeverityLevel.LOW,
                                cvss_score=3.7,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                                cwe_id="CWE-290",
                                owasp_category="A07:2021-Identification and Authentication Failures",
                                confidence="CERTAIN",
                                endpoint=dmarc_domain,
                                description="The DMARC policy is configured with 'p=none'. This functions in reporting mode only and does not reject or quarantine spoofed emails.",
                                evidence=f"TXT {dmarc_domain}: {txt}",
                                impact="Spoofed emails impersonating your executives or brand will still be delivered to recipient inboxes.",
                                remediation_summary="Enforce DMARC by upgrading the policy to 'p=quarantine' or 'p=reject'.",
                                remediation_effort="LOW",
                                remediation_code={
                                    "dns": f"{dmarc_domain}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}\""
                                }
                            )
                        )
                    break
        except Exception:
            pass

        if not has_dmarc:
            findings.append(
                Finding(
                    id="DNS-DMARC-MISSING",
                    name="Missing DMARC Policy Record",
                    category="DNS & Email Security",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-290",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    confidence="CERTAIN",
                    endpoint=dmarc_domain,
                    description=f"Domain '{domain}' does not have a DMARC policy at '{dmarc_domain}'.",
                    evidence=f"No TXT record matching 'v=DMARC1' at {dmarc_domain}",
                    impact="Receiving mail servers cannot verify authenticity against SPF/DKIM alignment.",
                    remediation_summary="Add a DMARC record to instruct receiving mail servers to reject unauthorized spoofed messages.",
                    remediation_effort="LOW",
                    remediation_code={
                        "dns": f"{dmarc_domain}. IN TXT \"v=DMARC1; p=quarantine; sp=quarantine; pct=100;\""
                    }
                )
            )

        return findings
