import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import List, Optional

from backend.models import Finding, SeverityLevel


class SSLTLSAuditor:
    """
    Audits SSL/TLS certificate validity, expiration, TLS protocol version, and cipher strength.
    Uses native Python ssl and socket modules without external dependencies.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def audit(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" or not parsed.scheme else 80)

        # If plain HTTP specified without port 443, test if HTTPS is available
        if parsed.scheme == "http" and port == 80:
            port = 443

        endpoint = f"https://{hostname}:{port}"

        try:
            context = ssl.create_default_context()
            # Allow fallback checks without throwing immediate unhandled exception
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # 1. Certificate Expiry and Validity
                    findings.extend(self._audit_cert_dates(cert, endpoint, hostname))

                    # 2. Protocol Version Check
                    findings.extend(self._audit_tls_protocol(protocol, endpoint))

                    # 3. Cipher Suite Strength Check
                    findings.extend(self._audit_cipher(cipher, endpoint))

                    # 4. SAN / Hostname verification
                    findings.extend(self._audit_subject_names(cert, hostname, endpoint))

        except ssl.SSLCertVerificationError as e:
            err_msg = str(e)
            if "certificate has expired" in err_msg.lower():
                findings.append(
                    Finding(
                        id="SSL-EXPIRED",
                        name="Critical: SSL/TLS Certificate Has Expired",
                        category="SSL/TLS",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=8.5,
                        endpoint=endpoint,
                        description="The SSL/TLS certificate for this domain has expired. Browsers will display an alarming security warning, blocking user traffic and destroying user trust.",
                        evidence=err_msg,
                        impact="Complete service disruption for HTTPS traffic and potential interception of credentials.",
                        remediation_summary="Renew the SSL certificate immediately via your CA (Let's Encrypt, Cloudflare, DigiCert).",
                        references=["https://letsencrypt.org/docs/"],
                    )
                )
            elif "self signed" in err_msg.lower():
                findings.append(
                    Finding(
                        id="SSL-SELF-SIGNED",
                        name="High: Self-Signed SSL Certificate Detected",
                        category="SSL/TLS",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.4,
                        endpoint=endpoint,
                        description="The server is utilizing a self-signed SSL/TLS certificate that is not trusted by public root authorities.",
                        evidence=err_msg,
                        impact="Users receive browser security warnings; subject to Man-In-The-Middle attacks.",
                        remediation_summary="Replace self-signed certificate with a trusted public CA certificate (e.g. Free Let's Encrypt / Certbot).",
                    )
                )
            elif "hostname" in err_msg.lower() or "doesn't match" in err_msg.lower():
                findings.append(
                    Finding(
                        id="SSL-HOSTNAME-MISMATCH",
                        name="High: SSL Certificate Hostname Mismatch",
                        category="SSL/TLS",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.1,
                        endpoint=endpoint,
                        description=f"The certificate presented does not match the requested hostname '{hostname}'.",
                        evidence=err_msg,
                        impact="Browsers will warn users that the connection is not private.",
                        remediation_summary="Issue a multi-domain (SAN) or wildcard certificate that includes this exact domain.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="SSL-VERIFY-FAIL",
                        name="SSL/TLS Certificate Verification Failed",
                        category="SSL/TLS",
                        severity=SeverityLevel.HIGH,
                        cvss_score=6.8,
                        endpoint=endpoint,
                        description=f"SSL certificate verification failed: {err_msg}",
                        evidence=err_msg,
                        impact="Potential trust chain failure or missing intermediate certificates.",
                        remediation_summary="Verify the full certificate bundle and intermediate chain.",
                    )
                )
        except Exception as e:
            # Non-TLS port or unreachable
            if parsed.scheme == "https":
                findings.append(
                    Finding(
                        id="SSL-UNREACHABLE",
                        name="Unable to Establish TLS Handshake",
                        category="SSL/TLS",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.0,
                        endpoint=endpoint,
                        description=f"TLS handshake could not be established on {hostname}:{port}: {str(e)}",
                        evidence=str(e),
                        impact="HTTPS services may be offline or restricted by a firewall.",
                        remediation_summary="Check firewall rules and verify port 443 is open.",
                    )
                )

        return findings

    def _audit_cert_dates(self, cert: dict, endpoint: str, hostname: str) -> List[Finding]:
        findings: List[Finding] = []
        if not cert or "notAfter" not in cert:
            return findings

        # Format: 'Mar 15 12:00:00 2027 GMT'
        not_after_str = cert["notAfter"]
        try:
            expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.now(datetime.timezone.utc)
            # Make expiry_date timezone-aware in UTC
            expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
            days_left = (expiry_date - now).days

            if days_left < 0:
                findings.append(
                    Finding(
                        id="SSL-EXPIRED-DATE",
                        name="Critical: SSL Certificate Expired",
                        category="SSL/TLS",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=8.5,
                        endpoint=endpoint,
                        description=f"Certificate expired {abs(days_left)} days ago on {not_after_str}.",
                        evidence=f"notAfter: {not_after_str} (expired)",
                        impact="Browsers block visits with privacy warnings.",
                        remediation_summary="Renew certificate immediately.",
                    )
                )
            elif days_left <= 14:
                findings.append(
                    Finding(
                        id="SSL-EXPIRING-IMMINENT",
                        name=f"High: SSL Certificate Expiring Soon ({days_left} days remaining)",
                        category="SSL/TLS",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.0,
                        endpoint=endpoint,
                        description=f"The SSL/TLS certificate will expire in {days_left} days ({not_after_str}).",
                        evidence=f"Expiration date: {not_after_str}",
                        impact="Service downtime will occur if renewal is missed.",
                        remediation_summary="Trigger automated renewal via certbot or hosting provider.",
                    )
                )
            elif days_left <= 30:
                findings.append(
                    Finding(
                        id="SSL-EXPIRING-WARNING",
                        name=f"Medium: SSL Certificate Expiring in {days_left} Days",
                        category="SSL/TLS",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=4.5,
                        endpoint=endpoint,
                        description=f"Certificate expires in {days_left} days on {not_after_str}.",
                        evidence=f"Expiration date: {not_after_str}",
                        impact="Requires attention to prevent unexpected expiration.",
                        remediation_summary="Ensure automated renewal cron jobs or ACME clients are scheduled.",
                    )
                )
        except Exception:
            pass

        return findings

    def _audit_tls_protocol(self, protocol: str, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(
                Finding(
                    id="TLS-DEPRECATED-VERSION",
                    name=f"High: Insecure Deprecated Protocol ({protocol})",
                    category="SSL/TLS",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    endpoint=endpoint,
                    description=f"Server negotiated connection using {protocol}. TLS 1.0 and 1.1 were officially deprecated by RFC 8996 due to vulnerabilities like POODLE and BEAST.",
                    evidence=f"Negotiated protocol: {protocol}",
                    impact="Attacker with network vantage point can downgrade encryption and intercept data.",
                    remediation_summary="Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                    remediation_code={
                        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    },
                )
            )
        return findings

    def _audit_cipher(self, cipher: tuple, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        if not cipher:
            return findings

        cipher_name = cipher[0]
        # Check for weak cipher indicators
        weak_keywords = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
        if any(weak in cipher_name for weak in weak_keywords):
            findings.append(
                Finding(
                    id="TLS-WEAK-CIPHER",
                    name=f"High: Weak Cipher Suite Negotiated ({cipher_name})",
                    category="SSL/TLS",
                    severity=SeverityLevel.HIGH,
                    cvss_score=6.9,
                    endpoint=endpoint,
                    description=f"The server allows connection with obsolete/weak cipher suite: '{cipher_name}'.",
                    evidence=f"Cipher: {cipher_name}",
                    impact="Susceptible to cryptographic breaks and cryptanalysis attacks.",
                    remediation_summary="Configure modern cipher suites with Forward Secrecy (ECDHE-ECDSA / ECDHE-RSA with AES-GCM or CHACHA20).",
                    remediation_code={
                        "nginx": "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';",
                    },
                )
            )

        return findings

    def _audit_subject_names(self, cert: dict, hostname: str, endpoint: str) -> List[Finding]:
        findings: List[Finding] = []
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        if sans and hostname not in sans:
            # Check wildcard match: *.example.com matches sub.example.com
            matched = False
            parts = hostname.split(".")
            if len(parts) >= 2:
                wildcard = f"*.{'.'.join(parts[1:])}"
                if wildcard in sans:
                    matched = True
            if not matched:
                findings.append(
                    Finding(
                        id="SSL-SAN-MISMATCH",
                        name="Medium: Requested Hostname Not Found in Certificate SANs",
                        category="SSL/TLS",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.5,
                        endpoint=endpoint,
                        description=f"Hostname '{hostname}' is not explicitly listed in certificate Subject Alternative Names: {', '.join(sans[:5])}",
                        evidence=f"Requested: {hostname}\nSANs: {', '.join(sans)}",
                        impact="Clients may reject the connection due to domain name mismatch.",
                        remediation_summary="Include all subdomains and aliases in the certificate's SAN extension.",
                    )
                )
        return findings
