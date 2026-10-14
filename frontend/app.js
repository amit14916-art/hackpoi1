// SecOps DAST SaaS - Client Controller
const API_BASE = window.location.protocol === "file:" ? "http://localhost:8000" : "";

let currentScanId = null;
let currentScanData = null;
let activeFilter = "all";
let pollInterval = null;
let currentChallenge = null;

document.addEventListener("DOMContentLoaded", () => {
  initScanForm();
  initFilterTabs();
  initDomainVerificationModal();
  initEnterpriseModal();
  initExportButtons();
});

// Helper for auth headers
function getHeaders(custom = {}) {
  const headers = { ...custom };
  const apiKey = localStorage.getItem("secops_api_key");
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  return headers;
}

// ==========================================
// Scan Initiation & Polling
// ==========================================

function initScanForm() {
  const form = document.getElementById("scan-form");
  const targetInput = document.getElementById("target-url");
  const btnStart = document.getElementById("btn-start-scan");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    let url = targetInput.value.trim();
    if (!url) return;

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
      targetInput.value = url;
    }

    const scanType = document.querySelector('input[name="scan-type"]:checked').value;
    const framework = document.getElementById("framework-select").value;

    btnStart.disabled = true;
    showProgressBox(true);
    hideResults();

    try {
      const resp = await fetch(`${API_BASE}/api/scan/start`, {
        method: "POST",
        headers: getHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          url: url,
          scan_type: scanType,
          framework_hint: framework,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Failed to initiate scan." }));
        throw new Error(err.detail || `Server returned ${resp.status}`);
      }

      const data = await resp.json();
      currentScanId = data.scan_id;
      startPolling(currentScanId);

    } catch (err) {
      if (err.message === "Failed to fetch" || err.name === "TypeError") {
        alert("⚠️ Backend server is offline!\n\nPlease start the server in your terminal:\n  python run_server.py\n\nThen open: http://localhost:8000");
      } else {
        alert("Scan error: " + err.message);
      }
      btnStart.disabled = false;
      showProgressBox(false);
    }
  });
}

function showProgressBox(show) {
  const box = document.getElementById("progress-box");
  if (show) {
    box.classList.remove("hidden");
    updateProgress(10, "Submitting target to audit pipeline...");
  } else {
    box.classList.add("hidden");
  }
}

function updateProgress(percent, stepDesc) {
  const fill = document.getElementById("progress-bar-fill");
  const percentText = document.getElementById("progress-percent-label");
  const stepText = document.getElementById("current-step-label");

  if (fill) fill.style.width = `${percent}%`;
  if (percentText) percentText.innerText = `${percent}%`;
  if (stepText) stepText.innerText = stepDesc;
}

function startPolling(scanId) {
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/scan/${scanId}/status`, {
        headers: getHeaders(),
      });
      if (!resp.ok) return;

      const statusData = await resp.json();
      updateProgress(statusData.progress, statusData.current_step);

      if (statusData.status === "COMPLETED") {
        clearInterval(pollInterval);
        document.getElementById("btn-start-scan").disabled = false;
        setTimeout(async () => {
          showProgressBox(false);
          await fetchAndRenderResults(scanId);
        }, 500);
      } else if (statusData.status === "FAILED") {
        clearInterval(pollInterval);
        document.getElementById("btn-start-scan").disabled = false;
        alert("Scan encountered an issue: " + (statusData.error || "Unknown error"));
        showProgressBox(false);
      }
    } catch (e) {
      console.error("Polling error", e);
    }
  }, 1200);
}

// ==========================================
// Results Rendering
// ==========================================

async function fetchAndRenderResults(scanId) {
  try {
    const resp = await fetch(`${API_BASE}/api/scan/${scanId}/results`, {
      headers: getHeaders(),
    });
    if (!resp.ok) throw new Error("Could not fetch scan results.");

    currentScanData = await resp.json();
    renderOverview(currentScanData);
    renderFindings(currentScanData.findings);
    showResults();
  } catch (e) {
    alert("Error loading findings: " + e.message);
  }
}

function showResults() {
  const section = document.getElementById("results-view");
  section.classList.remove("hidden");
  section.scrollIntoView({ behavior: "smooth" });
}

function hideResults() {
  const section = document.getElementById("results-view");
  section.classList.add("hidden");
}

function renderOverview(data) {
  const gradeEl = document.getElementById("score-grade-text");
  const scoreEl = document.getElementById("score-number-text");
  const domainEl = document.getElementById("scan-domain-label");
  const dateEl = document.getElementById("scan-meta-date");
  const idEl = document.getElementById("scan-meta-id");
  const verifiedEl = document.getElementById("scan-meta-verified");

  if (gradeEl) gradeEl.innerText = data.grade;
  if (scoreEl) scoreEl.innerText = `Score: ${data.score} / 100`;
  if (domainEl) domainEl.innerText = data.domain;
  if (dateEl) dateEl.innerText = `Date: ${data.started_at ? data.started_at.split("T")[0] : "-"}`;
  if (idEl) idEl.innerText = `ID: ${data.scan_id}`;

  if (verifiedEl) {
    if (data.is_domain_verified) {
      verifiedEl.innerText = "Verified Domain (Full DAST)";
      verifiedEl.style.color = "#34d399";
    } else {
      verifiedEl.innerText = "Unverified Domain (Passive Only)";
      verifiedEl.style.color = "#94a3b8";
    }
  }

  // Grade color
  const gradeColors = {
    "A+": "#10b981", "A": "#10b981", "B": "#38bdf8",
    "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"
  };
  if (gradeEl) gradeEl.style.color = gradeColors[data.grade] || "#94a3b8";

  // Counts
  const s = data.findings_summary || {};
  document.getElementById("stat-critical").innerText = s.critical || 0;
  document.getElementById("stat-high").innerText = s.high || 0;
  document.getElementById("stat-medium").innerText = s.medium || 0;
  document.getElementById("stat-low").innerText = s.low || 0;
  document.getElementById("stat-info").innerText = s.info || 0;

  // Filter counters
  document.getElementById("count-all").innerText = s.total || 0;
  document.getElementById("count-high-crit").innerText = (s.critical || 0) + (s.high || 0);

  // Executive Brief
  const briefEl = document.getElementById("brief-content");
  if (briefEl) briefEl.innerText = data.executive_overview || "Executive assessment synthesized successfully.";
}

function renderFindings(findings) {
  const container = document.getElementById("findings-container");
  container.innerHTML = "";

  const filtered = filterFindings(findings || [], activeFilter);

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 48px; background: rgba(16, 24, 40, 0.6); border-radius: 16px; border: 1px solid rgba(56, 189, 248, 0.1);">
        <span style="font-size: 32px;">🛡️</span>
        <h3 style="color: #f8fafc; margin-top: 12px;">No Findings in this Category</h3>
        <p style="color: #94a3b8; font-size: 14px; margin-top: 4px;">Target passed all security baseline checks for the selected filter.</p>
      </div>
    `;
    return;
  }

  filtered.forEach((f, idx) => {
    const card = document.createElement("div");
    card.className = "finding-item";

    const sevColors = {
      CRITICAL: { bg: "rgba(239, 68, 68, 0.15)", border: "rgba(239, 68, 68, 0.4)", text: "#f87171" },
      HIGH: { bg: "rgba(249, 115, 22, 0.15)", border: "rgba(249, 115, 22, 0.4)", text: "#fb923c" },
      MEDIUM: { bg: "rgba(245, 158, 11, 0.15)", border: "rgba(245, 158, 11, 0.4)", text: "#fbbf24" },
      LOW: { bg: "rgba(59, 130, 246, 0.15)", border: "rgba(59, 130, 246, 0.4)", text: "#60a5fa" },
      INFO: { bg: "rgba(100, 116, 139, 0.15)", border: "rgba(100, 116, 139, 0.4)", text: "#94a3b8" },
    };
    const c = sevColors[f.severity] || sevColors.INFO;

    let patchHtml = "";
    if (f.remediation_code && Object.keys(f.remediation_code).length > 0) {
      let codeTabs = "";
      let codeBlocks = "";
      Object.entries(f.remediation_code).forEach(([lang, code], cIdx) => {
        codeTabs += `<button class="patch-tab ${cIdx === 0 ? 'active' : ''}" data-lang="${lang}">${lang}</button>`;
        codeBlocks += `<pre class="patch-block ${cIdx === 0 ? '' : 'hidden'}" data-lang="${lang}"><code>${escapeHtml(code)}</code></pre>`;
      });
      patchHtml = `
        <div class="patch-container" style="margin-top: 14px; background: rgba(8, 14, 28, 0.95); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: #38bdf8; font-size: 13px;">🛠️ AI-Generated Remediation Patch:</strong>
          </div>
          ${codeBlocks}
        </div>
      `;
    }

    card.innerHTML = `
      <div class="finding-head" style="padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255, 255, 255, 0.05);">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <span style="font-size: 11px; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: ${c.bg}; border: 1px solid ${c.border}; color: ${c.text};">
            ${f.severity}
          </span>
          <strong style="font-size: 15px; color: #f8fafc;">${escapeHtml(f.name)}</strong>
          ${f.cwe_id ? `<span class="badge-cwe">${f.cwe_id}</span>` : ''}
          ${f.owasp_category ? `<span class="badge-owasp">${escapeHtml(f.owasp_category)}</span>` : ''}
        </div>
        <span style="color: #94a3b8; font-size: 13px; font-family: var(--font-mono);">Score: ${f.cvss_score || 0.0}</span>
      </div>
      <div style="padding: 16px 20px;">
        <p style="color: #cbd5e1; font-size: 14px; margin-bottom: 8px;">${escapeHtml(f.description)}</p>
        <div style="font-size: 12px; color: #94a3b8; margin-bottom: 6px;">
          <strong>Affected Endpoint:</strong> <code style="color: #38bdf8; font-family: var(--font-mono);">${escapeHtml(f.endpoint)}</code>
        </div>
        ${f.remediation_summary ? `<div style="font-size: 13px; color: #a7f3d0; margin-top: 6px;"><strong>Fix Recommendation:</strong> ${escapeHtml(f.remediation_summary)}</div>` : ''}
        ${f.evidence ? `<div class="proof-container"><div class="proof-label">Evidence / Observation:</div><code style="color: #cbd5e1; font-size: 12px;">${escapeHtml(f.evidence)}</code></div>` : ''}
        ${patchHtml}
      </div>
    `;

    container.appendChild(card);
  });
}

function filterFindings(findings, filter) {
  if (filter === "high-crit") {
    return findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH");
  } else if (filter === "headers") {
    return findings.filter(f => f.category && f.category.toLowerCase().includes("header"));
  } else if (filter === "ssl") {
    return findings.filter(f => f.category && (f.category.toLowerCase().includes("ssl") || f.category.toLowerCase().includes("tls")));
  } else if (filter === "sensitive") {
    return findings.filter(f => f.category && f.category.toLowerCase().includes("sensitive"));
  }
  return findings;
}

function initFilterTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      activeFilter = tab.dataset.filter;
      if (currentScanData) {
        renderFindings(currentScanData.findings);
      }
    });
  });
}

// ==========================================
// Export Triggers
// ==========================================

function initExportButtons() {
  document.getElementById("btn-export-markdown").addEventListener("click", () => {
    if (!currentScanId) return;
    window.open(`${API_BASE}/api/scan/${currentScanId}/export/markdown`, "_blank");
  });

  document.getElementById("btn-export-html").addEventListener("click", () => {
    if (!currentScanId) return;
    window.open(`${API_BASE}/api/scan/${currentScanId}/export/html`, "_blank");
  });

  document.getElementById("btn-export-soc2").addEventListener("click", () => {
    if (!currentScanId) return;
    window.open(`${API_BASE}/api/scan/${currentScanId}/export/compliance?framework=soc2`, "_blank");
  });

  document.getElementById("btn-export-iso27001").addEventListener("click", () => {
    if (!currentScanId) return;
    window.open(`${API_BASE}/api/scan/${currentScanId}/export/compliance?framework=iso27001`, "_blank");
  });

  document.getElementById("btn-export-json").addEventListener("click", () => {
    if (!currentScanData) return;
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security_audit_${currentScanData.domain}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// ==========================================
// Domain Verification (Legal Guardrail)
// ==========================================

function initDomainVerificationModal() {
  const modal = document.getElementById("verify-modal");
  const btnOpen = document.getElementById("btn-open-verify-modal");
  const btnClose = document.getElementById("btn-close-verify-modal");
  const btnGenerate = document.getElementById("btn-generate-challenge");
  const btnVerifyNow = document.getElementById("btn-verify-now");
  const domainInput = document.getElementById("verify-domain-input");
  const challengeDetails = document.getElementById("challenge-details");
  const alertEl = document.getElementById("verify-alert");

  btnOpen.addEventListener("click", () => {
    modal.classList.add("active");
    const targetUrl = document.getElementById("target-url").value;
    if (targetUrl) {
      try {
        const u = targetUrl.startsWith("http") ? targetUrl : "https://" + targetUrl;
        domainInput.value = new URL(u).hostname;
      } catch (e) {}
    }
  });

  btnClose.addEventListener("click", () => modal.classList.remove("active"));

  btnGenerate.addEventListener("click", async () => {
    const domain = domainInput.value.trim();
    if (!domain) {
      alert("Please enter a domain name.");
      return;
    }

    try {
      btnGenerate.disabled = true;
      const resp = await fetch(`${API_BASE}/api/verify/generate?domain=${encodeURIComponent(domain)}`, {
        method: "POST",
        headers: getHeaders(),
      });
      currentChallenge = await resp.json();

      document.getElementById("challenge-file-path").innerText = currentChallenge.http_file_path;
      document.getElementById("challenge-file-content").innerText = currentChallenge.http_file_content;
      document.getElementById("challenge-dns-name").innerText = currentChallenge.dns_record_name;
      document.getElementById("challenge-dns-value").innerText = currentChallenge.dns_record_value;

      challengeDetails.classList.remove("hidden");
      btnGenerate.disabled = false;
    } catch (e) {
      alert("Failed to generate challenge: " + e.message);
      btnGenerate.disabled = false;
    }
  });

  btnVerifyNow.addEventListener("click", async () => {
    if (!currentChallenge) return;
    btnVerifyNow.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/api/verify/check`, {
        method: "POST",
        headers: getHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          domain: currentChallenge.domain,
          token: currentChallenge.token,
          method: "HTTP_FILE",
        }),
      });

      const res = await resp.json();
      alertEl.style.display = "block";
      if (res.verified) {
        alertEl.className = "verify-alert success";
        alertEl.innerText = `✅ Ownership verified successfully for ${res.domain}! Full Active DAST testing unlocked.`;
      } else {
        alertEl.className = "verify-alert error";
        alertEl.innerText = `❌ Verification challenge check failed: ${res.message}`;
      }
    } catch (e) {
      alert("Verification request error: " + e.message);
    } finally {
      btnVerifyNow.disabled = false;
    }
  });
}

// ==========================================
// Enterprise Hub Modal
// ==========================================

function initEnterpriseModal() {
  const modal = document.getElementById("enterprise-modal");
  const btnOpen = document.getElementById("btn-open-enterprise-modal");
  const btnClose = document.getElementById("btn-close-enterprise-modal");
  const orgInput = document.getElementById("cfg-org-id");
  const keyInput = document.getElementById("cfg-api-key");
  const btnSaveAuth = document.getElementById("btn-save-auth");
  const authStatus = document.getElementById("auth-status-lbl");
  const btnConnectGh = document.getElementById("btn-connect-github");
  const slackInput = document.getElementById("cfg-slack-url");
  const btnSaveSlack = document.getElementById("btn-save-slack");
  const slackStatus = document.getElementById("slack-status-lbl");
  const webhookUrl = document.getElementById("deploy-webhook-url");

  // Load saved credentials
  const savedOrg = localStorage.getItem("secops_org_id") || "default-org";
  const savedKey = localStorage.getItem("secops_api_key") || "";
  orgInput.value = savedOrg;
  keyInput.value = savedKey;
  if (webhookUrl) {
    webhookUrl.innerText = `${API_BASE || 'http://localhost:8000'}/api/webhooks/deploy/${savedOrg}`;
  }

  btnOpen.addEventListener("click", () => modal.classList.add("active"));
  btnClose.addEventListener("click", () => modal.classList.remove("active"));

  btnSaveAuth.addEventListener("click", () => {
    const org = orgInput.value.trim() || "default-org";
    const key = keyInput.value.trim();
    localStorage.setItem("secops_org_id", org);
    if (key) localStorage.setItem("secops_api_key", key);
    else localStorage.removeItem("secops_api_key");

    if (webhookUrl) {
      webhookUrl.innerText = `${API_BASE || 'http://localhost:8000'}/api/webhooks/deploy/${org}`;
    }
    authStatus.innerText = "Credentials saved to browser session.";
    setTimeout(() => { authStatus.innerText = ""; }, 3000);
  });

  btnConnectGh.addEventListener("click", async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/github/connect`, {
        method: "POST",
        headers: getHeaders(),
      });
      const data = await resp.json();
      if (data.install_url) {
        window.open(data.install_url, "_blank");
      }
    } catch (e) {
      alert("GitHub Connect Error: " + e.message);
    }
  });

  btnSaveSlack.addEventListener("click", async () => {
    const slackUrl = slackInput.value.trim();
    if (!slackUrl) return;
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/cicd/notifications`, {
        method: "PATCH",
        headers: getHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ slack_webhook_url: slackUrl }),
      });
      if (resp.ok) {
        slackStatus.innerText = "Slack notification webhook saved.";
        setTimeout(() => { slackStatus.innerText = ""; }, 3000);
      }
    } catch (e) {
      alert("Failed to save Slack settings: " + e.message);
    }
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
