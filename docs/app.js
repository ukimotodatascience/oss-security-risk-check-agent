// Static Client-side Logic for OSS Security Checker (GitHub Pages Compatible)

document.addEventListener("DOMContentLoaded", () => {
  let currentScanData = null;

  // DOM Elements
  const repoUrlEl = document.getElementById("repo-url");
  const scannedAtEl = document.getElementById("scanned-at");
  const overallScoreNumEl = document.getElementById("overall-score-num");
  const circleProgressEl = document.getElementById("circle-progress");
  const statusBadgeEl = document.getElementById("overall-status-badge");
  const statusReasonEl = document.getElementById("overall-status-reason");
  const categoriesGridEl = document.getElementById("categories-grid");
  const findingsListEl = document.getElementById("findings-list");
  const categoryFilterEl = document.getElementById("category-filter");
  const severityFilterEl = document.getElementById("severity-filter");
  const btnLoadSampleEl = document.getElementById("btn-load-sample");
  const fileInputEl = document.getElementById("file-input");

  // Initial Load: scan_result.json を取得
  loadScanResult("scan_result.json");

  // Event Listeners
  if (btnLoadSampleEl) {
    btnLoadSampleEl.addEventListener("click", () => {
      loadScanResult("scan_result.json");
    });
  }

  if (fileInputEl) {
    fileInputEl.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (evt) => {
        try:
          const data = JSON.parse(evt.target.result);
          renderScanResult(data);
        } catch (err) {
          alert("有効なJSONファイルを選択してください: " + err.message);
        }
      };
      reader.readAsText(file);
    });
  }

  if (categoryFilterEl) {
    categoryFilterEl.addEventListener("change", () => filterAndRenderFindings());
  }

  if (severityFilterEl) {
    severityFilterEl.addEventListener("change", () => filterAndRenderFindings());
  }

  // JSONデータのロード
  async function loadScanResult(url) {
    try {
      const res = await fetch(url + "?t=" + Date.now());
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      renderScanResult(data);
    } catch (err) {
      console.warn("Could not load scan_result.json automatically. Rendering fallback/demo state.", err);
      renderScanResult(getFallbackData());
    }
  }

  // 画面全体へのデータ反映
  function renderScanResult(data) {
    currentScanData = data;

    // Header & Meta
    repoUrlEl.textContent = data.repository_url || "Target Repository";
    scannedAtEl.textContent = `最終診断日時: ${data.scanned_at || "N/A"}`;

    // Overall Score & Circle Animation
    const score = Number(data.overall_score || 0);
    overallScoreNumEl.textContent = score.toFixed(1);

    // SVG Circumference = 2 * PI * 70 = 439.82 (approx 440)
    const circumference = 440;
    const offset = circumference - (score / 10.0) * circumference;
    circleProgressEl.style.strokeDasharray = `${circumference}`;
    circleProgressEl.style.strokeDashoffset = `${offset}`;

    // Status Badge & Reason
    const status = data.status || "普通";
    statusBadgeEl.textContent = status;
    statusBadgeEl.className = "status-badge";

    if (status === "安全" || status === "SAFE") {
      statusBadgeEl.classList.add("status-safe");
      circleProgressEl.style.stroke = "var(--color-safe)";
    } else if (status === "普通" || status === "MODERATE") {
      statusBadgeEl.classList.add("status-moderate");
      circleProgressEl.style.stroke = "var(--color-moderate)";
    } else {
      statusBadgeEl.classList.add("status-dangerous");
      circleProgressEl.style.stroke = "var(--color-danger)";
    }

    statusReasonEl.textContent = data.status_reason || "";

    // 8 Categories Render
    renderCategories(data.categories || {});

    // Findings Render
    filterAndRenderFindings();
  }

  // 8カテゴリカードの動的描画
  function renderCategories(categoriesObj) {
    categoriesGridEl.innerHTML = "";

    const categoryKeys = [
      "known_vulnerabilities",
      "secrets",
      "misconfiguration",
      "dependencies",
      "development",
      "cicd",
      "maintenance",
      "source_code"
    ];

    categoryKeys.forEach(key => {
      const catData = categoriesObj[key] || {
        category_name: key,
        score: 10.0,
        findings_count: 0,
        summary: "データなし"
      };

      const card = document.createElement("div");
      card.className = "category-card";

      const score = Number(catData.score || 0);
      let colorClass = "var(--color-safe)";
      let bgScoreClass = "var(--color-safe-bg)";
      if (score < 5.0) {
        colorClass = "var(--color-danger)";
        bgScoreClass = "var(--color-danger-bg)";
      } else if (score < 7.5) {
        colorClass = "var(--color-moderate)";
        bgScoreClass = "var(--color-moderate-bg)";
      }

      card.innerHTML = `
        <div class="cat-header">
          <div class="cat-title">${escapeHtml(catData.category_name)}</div>
          <div class="cat-score-badge" style="color: ${colorClass}; background: ${bgScoreClass};">
            ${score.toFixed(1)}
          </div>
        </div>
        <div class="cat-progress-bg">
          <div class="cat-progress-bar" style="width: ${(score * 10)}%; background: ${colorClass};"></div>
        </div>
        <div class="cat-footer">
          <span>${escapeHtml(catData.summary || "")}</span>
          <span class="findings-count-tag">${escapeHtml(catData.findings_count || 0)} 指摘</span>
        </div>
      `;

      // クリックで該当カテゴリのFindingにフィルター絞り込み
      card.addEventListener("click", () => {
        if (categoryFilterEl) {
          categoryFilterEl.value = key;
          filterAndRenderFindings();
          document.getElementById("findings-section").scrollIntoView({ behavior: "smooth" });
        }
      });

      categoriesGridEl.appendChild(card);
    });
  }

  // Finding一覧のフィルタリングと描画
  function filterAndRenderFindings() {
    if (!currentScanData) return;

    findingsListEl.innerHTML = "";

    const selectedCat = categoryFilterEl ? categoryFilterEl.value : "ALL";
    const selectedSev = severityFilterEl ? severityFilterEl.value : "ALL";

    const allFindings = currentScanData.all_findings || [];

    const filtered = allFindings.filter(f => {
      const matchCat = (selectedCat === "ALL" || f.category === selectedCat);
      const matchSev = (selectedSev === "ALL" || (f.severity && f.severity.toUpperCase() === selectedSev));
      return matchCat && matchSev;
    });

    if (filtered.length === 0) {
      findingsListEl.innerHTML = `<div class="empty-findings">該当する指摘事項 (Findings) はありません。診断結果は良好です！</div>`;
      return;
    }

    filtered.forEach(f => {
      const card = document.createElement("div");
      const sev = (f.severity || "INFO").toUpperCase();
      card.className = `finding-card sev-${sev}`;

      const targetHtml = f.target ? `<div class="finding-target">📄 ${escapeHtml(f.target)} ${f.location ? '(' + escapeHtml(f.location) + ')' : ''}</div>` : '';
      const remedHtml = f.remediation ? `<div class="finding-remediation">💡 対策案内: ${escapeHtml(f.remediation)}</div>` : '';

      card.innerHTML = `
        <div class="finding-meta">
          <span class="sev-tag ${sev}">${sev}</span>
          <span class="cat-pill">${escapeHtml(f.category || "")}</span>
          <span class="rule-id">${escapeHtml(f.rule_id || "")}</span>
          <span class="label-muted" style="margin-left: auto;">[${escapeHtml(f.source || "")}]</span>
        </div>
        <div class="finding-title">${escapeHtml(f.title || f.rule_id)}</div>
        <div class="finding-desc">${escapeHtml(f.description || "")}</div>
        ${targetHtml}
        ${remedHtml}
      `;

      findingsListEl.appendChild(card);
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

  function getFallbackData() {
    return {
      repository_url: "https://github.com/ukimotodatascience/oss-security-risk-check-agent",
      scanned_at: "2026-09-05 17:00:00 UTC",
      overall_score: 7.8,
      status: "安全",
      status_reason: "全体としてセキュリティ対策・プロジェクト健全性が非常に良好です (7.8 点)。",
      categories: {
        known_vulnerabilities: { category_name: "既知脆弱性", score: 8.5, findings_count: 1, summary: "Trivyで1件のLow既知脆弱性検出" },
        secrets: { category_name: "機密情報・Secret管理", score: 10.0, findings_count: 0, summary: "問題なし" },
        misconfiguration: { category_name: "設定セキュリティ", score: 10.0, findings_count: 0, summary: "問題なし" },
        dependencies: { category_name: "依存関係・Supply Chain", score: 7.0, findings_count: 1, summary: "Scorecard: 依存固定の向上を推薦" },
        development: { category_name: "開発・変更管理", score: 9.0, findings_count: 0, summary: "Code Review / PR保護有効" },
        cicd: { category_name: "CI/CD・リリースセキュリティ", score: 7.5, findings_count: 1, summary: "Scorecard: 最小権限トークン設定推奨" },
        maintenance: { category_name: "プロジェクト保守体制", score: 9.0, findings_count: 0, summary: "SECURITY.md存在" },
        source_code: { category_name: "ソースコードセキュリティ", score: 6.8, findings_count: 2, summary: "自作ルール: コード内改善点2件" }
      },
      all_findings: [
        { category: "known_vulnerabilities", source: "trivy", rule_id: "CVE-2023-12345", severity: "LOW", title: "Minor dependency vulnerability", target: "package-lock.json", description: "Low severity vuln in demo dependency", remediation: "Update package to 1.2.3" },
        { category: "source_code", source: "rule_based", rule_id: "RB-CMD-001", severity: "HIGH", title: "Command Injection Check", target: "src/utils/exec.py", location: "Line 15", description: "Subprocess shell call detected", remediation: "Avoid shell=True" }
      ]
    };
  }
});
