import pytest
import httpx

from backend.main import app, scan_jobs
from backend.models import ScanResult, Finding, ScanStatus, SeverityLevel
from backend.reporting.compliance import ComplianceEvaluator, LEGAL_AUDIT_DISCLAIMER
from backend.reporting.report_generator import ReportGenerator
from backend.db.session import init_db


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_soc2_mapping_and_evaluation():
    result = ScanResult(
        scan_id="compliance_test_001",
        target_url="https://compliance.local",
        domain="compliance.local",
        status=ScanStatus.COMPLETED,
        started_at="2026-09-26T12:00:00Z",
        findings=[
            Finding(
                id="ACTIVE-SQLI-01",
                name="SQL Injection in /api/data",
                category="Injection",
                severity=SeverityLevel.CRITICAL,
                cwe_id="CWE-89",
                endpoint="https://compliance.local/api/data",
                description="SQLi detected",
            ),
            Finding(
                id="SECRET-API-KEY",
                name="Exposed API Key",
                category="Secrets",
                severity=SeverityLevel.HIGH,
                cwe_id="CWE-798",
                endpoint="https://compliance.local/app.js",
                description="Hardcoded API Key",
            ),
        ]
    )

    eval_soc2 = ComplianceEvaluator.evaluate_soc2(result)
    assert eval_soc2["framework"].startswith("SOC 2")
    assert eval_soc2["fail_count"] >= 2
    # CC6.6 (Injection) and CC6.1 (Access Controls / Secrets) must fail
    assert eval_soc2["controls"]["CC6.6"]["status"] == "Fail"
    assert eval_soc2["controls"]["CC6.1"]["status"] == "Fail"


def test_iso27001_mapping_and_evaluation():
    result = ScanResult(
        scan_id="compliance_test_002",
        target_url="https://compliance.local",
        domain="compliance.local",
        status=ScanStatus.COMPLETED,
        started_at="2026-09-26T12:00:00Z",
        findings=[
            Finding(
                id="DMARC-MISSING",
                name="Missing DMARC Policy",
                category="Email Security",
                severity=SeverityLevel.HIGH,
                cwe_id="CWE-290",
                endpoint="https://compliance.local",
                description="Missing DMARC",
            ),
        ]
    )

    eval_iso = ComplianceEvaluator.evaluate_iso27001(result)
    assert "ISO/IEC 27001:2022" in eval_iso["framework"]
    # A.8.20 (Network Security & Domain Boundaries) should fail due to CWE-290
    assert eval_iso["controls"]["A.8.20"]["status"] == "Fail"


def test_compliance_pdf_generation_bytes_and_disclaimer():
    result = ScanResult(
        scan_id="compliance_test_003",
        target_url="https://acme.org",
        domain="acme.org",
        status=ScanStatus.COMPLETED,
        started_at="2026-09-26T12:00:00Z",
        score=95,
        grade="A",
        findings=[]
    )

    # Test SOC 2 PDF
    soc2_pdf = ReportGenerator.to_soc2_report(result, "Acme International")
    assert isinstance(soc2_pdf, bytes)
    assert len(soc2_pdf) > 200
    assert soc2_pdf.startswith(b"%PDF")

    # Test ISO 27001 PDF
    iso_pdf = ReportGenerator.to_iso27001_report(result, "Acme International")
    assert isinstance(iso_pdf, bytes)
    assert len(iso_pdf) > 200
    assert iso_pdf.startswith(b"%PDF")

    # Verify disclaimer constant
    assert "DOES NOT constitute a certified audit" in LEGAL_AUDIT_DISCLAIMER


@pytest.mark.asyncio
async def test_compliance_export_endpoints():
    scan_id = "test_export_compliance_001"
    res = ScanResult(
        scan_id=scan_id,
        target_url="https://example.com",
        domain="example.com",
        status=ScanStatus.COMPLETED,
        started_at="2026-09-26T12:00:00Z",
    )
    scan_jobs[scan_id] = res

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # SOC 2 export
        resp_soc2 = await client.get(f"/api/scan/{scan_id}/export/compliance?framework=soc2")
        assert resp_soc2.status_code == 200
        assert resp_soc2.headers["content-type"] == "application/pdf"
        assert resp_soc2.content.startswith(b"%PDF")

        # ISO 27001 export
        resp_iso = await client.get(f"/api/scan/{scan_id}/export/compliance?framework=iso27001")
        assert resp_iso.status_code == 200
        assert resp_iso.headers["content-type"] == "application/pdf"
        assert resp_iso.content.startswith(b"%PDF")
