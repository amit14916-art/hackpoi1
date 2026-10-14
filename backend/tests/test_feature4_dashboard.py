import pytest
import httpx
from datetime import datetime

from backend.main import app
from backend.db.session import init_db, SessionLocal
from backend.db.models import Domain, Scan, Organization
from backend.models import ScanStatus


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


@pytest.mark.asyncio
async def test_org_domains_crud_and_history():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Add domain to default-org
        add_resp = await client.post(
            "/api/org/default-org/domains",
            json={"url": "https://dashboard-test.com"}
        )
        assert add_resp.status_code == 201
        dom_data = add_resp.json()
        assert dom_data["domain_name"] == "dashboard-test.com"
        dom_id = dom_data["id"]

        # 2. List domains
        list_resp = await client.get("/api/org/default-org/domains")
        assert list_resp.status_code == 200
        all_doms = list_resp.json()
        assert any(d["id"] == dom_id for d in all_doms)

        # 3. Insert mock historical scans for this domain
        db = SessionLocal()
        try:
            s1 = Scan(
                scan_id="scan_hist_01",
                org_id="default-org",
                target_url="https://dashboard-test.com",
                domain="dashboard-test.com",
                status=ScanStatus.COMPLETED.value,
                started_at="2026-09-20T10:00:00Z",
                completed_at="2026-09-20T10:05:00Z",
                score=75,
                grade="B",
                findings_summary={"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 2},
            )
            s2 = Scan(
                scan_id="scan_hist_02",
                org_id="default-org",
                target_url="https://dashboard-test.com",
                domain="dashboard-test.com",
                status=ScanStatus.COMPLETED.value,
                started_at="2026-09-26T10:00:00Z",
                completed_at="2026-09-26T10:05:00Z",
                score=95,
                grade="A",
                findings_summary={"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1},
            )
            db.merge(s1)
            db.merge(s2)
            db.commit()
        finally:
            db.close()

        # 4. Query domain history timeline
        hist_resp = await client.get(f"/api/org/default-org/domains/{dom_id}/history")
        assert hist_resp.status_code == 200
        history = hist_resp.json()
        assert len(history) >= 2
        assert history[0]["score"] == 75
        assert history[1]["score"] == 95

        # 5. Query Org Overview Aggregation
        overview_resp = await client.get("/api/org/default-org/overview")
        assert overview_resp.status_code == 200
        overview = overview_resp.json()
        assert overview["total_domains"] >= 1
        assert "avg_score" in overview
        assert "total_open_findings" in overview
        assert "trends" in overview
        assert "delta_7d" in overview["trends"]
