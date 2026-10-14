import secrets
import datetime
from typing import Dict, Optional
from urllib.parse import urlparse
import httpx

from backend.models import (
    VerificationChallenge,
    VerificationMethod,
    VerificationStatus,
)


class DomainVerifier:
    """
    Implements legal guardrails preventing unauthorized active vulnerability scans.
    Verifies domain ownership via DNS TXT records or HTTP .well-known challenges.
    """

    def __init__(self):
        # In-memory store (or persistent store in production)
        self._challenges: Dict[str, VerificationChallenge] = {}
        self._verified_domains: Dict[str, dict] = {}

    def normalize_domain(self, domain_or_url: str) -> str:
        raw = domain_or_url.strip().lower()
        if "://" in raw:
            parsed = urlparse(raw)
            raw = parsed.hostname or raw
        # Remove ports, trailing slashes
        return raw.split(":")[0].strip("/")

    def create_challenge(self, domain_or_url: str) -> VerificationChallenge:
        domain = self.normalize_domain(domain_or_url)
        token = secrets.token_hex(16)
        token_string = f"sec-verify={token}"

        challenge = VerificationChallenge(
            domain=domain,
            token=token,
            dns_record_name=f"_sec-verify.{domain}",
            dns_record_value=token_string,
            http_file_path=f"/.well-known/security-check.txt",
            http_file_content=token_string,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            status=VerificationStatus.PENDING,
        )

        self._challenges[domain] = challenge
        return challenge

    def get_challenge(self, domain_or_url: str) -> Optional[VerificationChallenge]:
        domain = self.normalize_domain(domain_or_url)
        return self._challenges.get(domain)

    def is_verified(self, domain_or_url: str) -> bool:
        domain = self.normalize_domain(domain_or_url)
        # Check if localhost / loopback for local dev testing
        if domain in ["localhost", "127.0.0.1", "0.0.0.0"]:
            return True
        return domain in self._verified_domains

    async def verify(self, domain_or_url: str, token: str, method: VerificationMethod = VerificationMethod.HTTP_FILE) -> tuple[bool, str]:
        domain = self.normalize_domain(domain_or_url)
        expected_token = f"sec-verify={token}"

        if method == VerificationMethod.HTTP_FILE:
            return await self._verify_http_file(domain, expected_token, token)
        elif method == VerificationMethod.DNS_TXT:
            return await self._verify_dns_txt(domain, expected_token, token)
        else:
            return False, "Unsupported verification method."

    async def _verify_http_file(self, domain: str, expected_full: str, raw_token: str) -> tuple[bool, str]:
        urls_to_try = [
            f"https://{domain}/.well-known/security-check.txt",
            f"http://{domain}/.well-known/security-check.txt",
        ]

        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
            last_err = ""
            for url in urls_to_try:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        content = resp.text.strip()
                        if expected_full in content or raw_token in content:
                            self._mark_verified(domain, "HTTP_FILE")
                            return True, f"Domain ownership confirmed via {url}."
                        else:
                            last_err = f"File found at {url} but content '{content[:40]}' did not match expected '{expected_full}'."
                    else:
                        last_err = f"Received HTTP {resp.status_code} at {url}."
                except Exception as e:
                    last_err = f"Connection failed to {url}: {str(e)}"

        return False, last_err or "Verification file not found or unreachable."

    async def _verify_dns_txt(self, domain: str, expected_full: str, raw_token: str) -> tuple[bool, str]:
        # Try DNS resolution using DNS-over-HTTPS (DoH) via Cloudflare/Google public DNS
        # This guarantees verification works across any OS without requiring root/custom socket configs
        record_names = [f"_sec-verify.{domain}", domain]

        async with httpx.AsyncClient(timeout=6.0) as client:
            for rname in record_names:
                try:
                    # Cloudflare DNS over HTTPS API
                    doh_url = f"https://cloudflare-dns.com/dns-query?name={rname}&type=TXT"
                    resp = await client.get(doh_url, headers={"accept": "application/dns-json"})
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        for ans in answers:
                            txt_data = ans.get("data", "").strip('"')
                            if expected_full in txt_data or raw_token in txt_data:
                                self._mark_verified(domain, "DNS_TXT")
                                return True, f"Domain ownership confirmed via DNS TXT record at {rname}."
                except Exception as e:
                    pass

        return False, f"DNS TXT record matching '{expected_full}' was not found for {domain} or _sec-verify.{domain}."

    def _mark_verified(self, domain: str, method: str):
        self._verified_domains[domain] = {
            "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": method,
        }
        if domain in self._challenges:
            self._challenges[domain].status = VerificationStatus.VERIFIED
