import re
import asyncio
from typing import List, Dict, Any, Set
import httpx

from backend.models import Finding, SeverityLevel


class SecretsScanner:
    """
    High-fidelity scanner that inspects web pages and client-side JavaScript assets
    for exposed credentials, API keys, private tokens, and secret parameters.
    Classified under CWE-798 (Use of Hard-coded Credentials) and OWASP A07:2021.
    """

    PATTERNS = [
        {
            "id": "SECRET-GOOGLE-API-KEY",
            "name": "Hardcoded Google Cloud / Firebase API Key",
            "regex": r'\b(AIza[0-9A-Za-z_\-]{30,38})\b',
            "severity": SeverityLevel.HIGH,
            "cvss": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "impact": "Exposed Google Cloud API keys can be abused by attackers to exhaust quotas, access Firestore/Firebase data, or incur unauthorized billing.",
            "remediation": "Restrict the API key to specific HTTP referrers or IP addresses in Google Cloud Console, and store sensitive credentials server-side.",
            "code": {
                "general": "// Store in environment variables, never hardcode:\nconst apiKey = process.env.GOOGLE_API_KEY;"
            }
        },
        {
            "id": "SECRET-AWS-ACCESS-KEY",
            "name": "Hardcoded AWS Access Key ID",
            "regex": r'\b(AKIA[0-9A-Z]{16})\b',
            "severity": SeverityLevel.CRITICAL,
            "cvss": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "impact": "Attackers can authenticate to AWS CLI/SDK, potentially accessing S3 buckets, EC2 instances, and databases if the corresponding secret key is known or IAM policies are loose.",
            "remediation": "Immediately revoke this access key in AWS IAM Console and rotate credentials.",
            "code": {
                "aws": "# Revoke in AWS IAM Console\naws iam delete-access-key --user-name <user> --access-key-id <AKIA...>"
            }
        },
        {
            "id": "SECRET-GITHUB-TOKEN",
            "name": "Hardcoded GitHub Personal Access Token",
            "regex": r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b',
            "severity": SeverityLevel.CRITICAL,
            "cvss": 9.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "impact": "Enables unauthorized access to private repositories, code cloning, and commit manipulation.",
            "remediation": "Revoke the token immediately from GitHub Settings -> Developer Settings -> Personal access tokens.",
        },
        {
            "id": "SECRET-STRIPE-LIVE-KEY",
            "name": "Hardcoded Stripe Live Secret Key",
            "regex": r'\b(sk_live_[0-9a-zA-Z]{24,34})\b',
            "severity": SeverityLevel.CRITICAL,
            "cvss": 9.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "impact": "Gives full unrestricted API access to customer payment methods, charges, balance transfers, and refunds.",
            "remediation": "Immediately roll this secret key in the Stripe Dashboard under Developers -> API keys.",
        },
        {
            "id": "SECRET-SLACK-WEBHOOK",
            "name": "Hardcoded Slack Incoming Webhook URL",
            "regex": r'(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)',
            "severity": SeverityLevel.HIGH,
            "cvss": 7.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "impact": "Attackers can spam internal private Slack channels with phishing messages or monitor alerts.",
            "remediation": "Regenerate the Slack webhook URL and restrict write permissions.",
        },
        {
            "id": "SECRET-PRIVATE-KEY",
            "name": "Exposed Cryptographic Private Key",
            "regex": r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)',
            "severity": SeverityLevel.CRITICAL,
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": "CWE-312",
            "owasp": "A02:2021-Cryptographic Failures",
            "impact": "Compromise of the private key allows attackers to impersonate servers or decrypt TLS/SSH communications.",
            "remediation": "Remove the private key immediately, rotate certificates, and deploy only the public key.",
        }
    ]

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecOpsAudit/2.0",
        }

    async def scan_assets(self, target_url: str, js_urls: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        visited_urls: Set[str] = set()

        raw_targets = [target_url] + js_urls[:10]
        targets = []
        for u in raw_targets:
            if u not in visited_urls:
                visited_urls.add(u)
                targets.append(u)

        sem = asyncio.Semaphore(5)

        async def _fetch_and_analyze(client: httpx.AsyncClient, url: str) -> List[Finding]:
            async with sem:
                try:
                    resp = await client.get(url, headers=self.headers)
                    if resp.status_code == 200:
                        return self._analyze_content(resp.text, url)
                except Exception:
                    pass
            return []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            tasks = [_fetch_and_analyze(client, url) for url in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    findings.extend(res)

        return findings

    def _analyze_content(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []

        for p in self.PATTERNS:
            matches = re.findall(p["regex"], content)
            if matches:
                # Deduplicate and mask match for security reporting
                raw_match = matches[0]
                if len(raw_match) > 8:
                    masked = raw_match[:4] + "*" * (len(raw_match) - 8) + raw_match[-4:]
                else:
                    masked = raw_match[:2] + "****"

                evidence_line = f"Pattern matched in {source_url}\nSample (masked): {masked}"

                findings.append(
                    Finding(
                        id=f"{p['id']}-{abs(hash(source_url)) % 10000}",
                        name=p["name"],
                        category="Secrets Exposure",
                        severity=p["severity"],
                        cvss_score=p["cvss"],
                        cvss_vector=p["cvss_vector"],
                        cwe_id=p["cwe"],
                        owasp_category=p["owasp"],
                        confidence="CERTAIN",
                        endpoint=source_url,
                        description=f"A hardcoded secret or API credential matching {p['name']} was detected in client-side code at {source_url}.",
                        evidence=evidence_line,
                        request_proof=f"GET {source_url} HTTP/1.1\nHost: {source_url.split('/')[2]}",
                        response_proof=f"HTTP/1.1 200 OK\n... {masked} ...",
                        impact=p["impact"],
                        remediation_summary=p["remediation"],
                        remediation_effort="LOW",
                        remediation_code=p.get("code", {}),
                        references=["https://cwe.mitre.org/data/definitions/798.html"]
                    )
                )

        return findings
