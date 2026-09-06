// Static Client-side Logic for OSS Security Checker (GitHub Pages Compatible)

document.addEventListener("DOMContentLoaded", () => {
  let currentScanData = null;
  let currentLoadId = 0;

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

      const loadId = ++currentLoadId;
      const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
      if (file.size > MAX_FILE_SIZE_BYTES) {
        alert("ファイルサイズが大きすぎます (上限: 10MB)。");
        renderErrorState("選択されたファイルサイズが上限 (10MB) を超えています。");
        fileInputEl.value = "";
        return;
      }

      const reader = new FileReader();
      reader.onload = (evt) => {
        if (loadId !== currentLoadId) return;
        try {
          const data = JSON.parse(evt.target.result);
          renderScanResult(data);
        } catch (err) {
          alert("有効なJSONファイルを選択してください: " + err.message);
          renderErrorState("選択されたファイルの解析に失敗しました: " + err.message);
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
    const loadId = ++currentLoadId;
    const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
    try {
      const res = await fetch(url + "?t=" + Date.now());
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const contentLength = res.headers.get("content-length");
      if (contentLength && parseInt(contentLength, 10) > MAX_FILE_SIZE_BYTES) {
        throw new Error("自動読み込みデータのサイズが上限 (10MB) を超えています。");
      }
      const text = await res.text();
      if (text.length > MAX_FILE_SIZE_BYTES) {
        throw new Error("自動読み込みデータのサイズが上限 (10MB) を超えています。");
      }
      const data = JSON.parse(text);
      if (loadId === currentLoadId) {
        renderScanResult(data);
      }
    } catch (err) {
      if (loadId === currentLoadId) {
        console.warn("Could not load scan_result.json automatically.", err);
        renderErrorState("スキャン結果データ (scan_result.json) を読み込めませんでした。JSONファイルを読み込むか再生成してください。");
      }
    }
  }

  function validateScanData(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) return false;
    if (typeof data.repository_url !== "string") return false;
    if (typeof data.overall_score !== "number" || !Number.isFinite(data.overall_score) || data.overall_score < 0 || data.overall_score > 10) return false;

    if (typeof data.status !== "string") return false;
    if (!data.categories || typeof data.categories !== "object" || Array.isArray(data.categories)) return false;

    const requiredKeys = [
      "known_vulnerabilities",
      "secrets",
      "misconfiguration",
      "dependencies",
      "development",
      "cicd",
      "maintenance",
      "source_code"
    ];
    for (const key of requiredKeys) {
      const catObj = data.categories[key];
      if (!catObj || typeof catObj !== "object" || Array.isArray(catObj)) return false;
      if (typeof catObj.score !== "number" || isNaN(catObj.score) || catObj.score < 0 || catObj.score > 10) return false;
      if (typeof catObj.evaluated !== "boolean") return false;
      if (typeof catObj.category !== "string") return false;
      if (catObj.findings && !Array.isArray(catObj.findings)) return false;
    }

    const findingsArray = data.all_findings || data.findings;
    if (!Array.isArray(findingsArray)) return false;
    for (const f of findingsArray) {
      if (!f || typeof f !== "object" || Array.isArray(f)) return false;
      if (typeof f.category !== "string") return false;
      if (typeof f.severity !== "string") return false;
      if (typeof f.title !== "string") return false;
    }
    return true;
  }

  function renderErrorState(message) {
    currentScanData = null;
    repoUrlEl.textContent = "Data Load Error";
    scannedAtEl.textContent = "最終診断日時: N/A";
    overallScoreNumEl.textContent = "0.0";
    circleProgressEl.style.strokeDashoffset = "440";
    circleProgressEl.style.stroke = "var(--text-dim)";

    statusBadgeEl.textContent = "評価不能";
    statusBadgeEl.className = "status-badge status-unknown";
    statusReasonEl.textContent = message;

    categoriesGridEl.innerHTML = `<div class="empty-findings" style="grid-column: 1/-1;">診断データが読み込まれていません。</div>`;
    findingsListEl.innerHTML = `<div class="empty-findings">${escapeHtml(message)}</div>`;
  }

  // 画面全体へのデータ反映
  function renderScanResult(data) {
    if (!validateScanData(data)) {
      renderErrorState("診断データ (JSON) の構造が正しくありません。");
      return;
    }

    currentScanData = data;

    // Header & Meta
    let repoDisplay = data.repository_url || "Target Repository";
    const extraMeta = [];
    if (data.scanned_ref) extraMeta.push(`ref: ${data.scanned_ref}`);
    if (data.scanned_subdir) extraMeta.push(`subdir: ${data.scanned_subdir}`);
    if (extraMeta.length > 0) {
      repoDisplay += ` (${extraMeta.join(", ")})`;
    }
    repoUrlEl.textContent = repoDisplay;
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
    } else if (status === "評価不能" || status === "UNKNOWN") {
      statusBadgeEl.classList.add("status-unknown");
      circleProgressEl.style.stroke = "var(--text-dim)";
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
        score: 0.0,
        evaluated: false,
        findings_count: 0,
        summary: "未評価"
      };

      const card = document.createElement("div");
      card.className = "category-card";

      const evaluated = catData.evaluated !== false;
      const score = Number(catData.score || 0);

      let scoreBadgeText = evaluated ? score.toFixed(1) : "N/A";
      let colorClass = "var(--color-safe)";
      let bgScoreClass = "var(--color-safe-bg)";
      let barWidth = evaluated ? (score * 10) : 0;

      if (!evaluated) {
        colorClass = "var(--text-dim)";
        bgScoreClass = "rgba(255, 255, 255, 0.05)";
      } else if (score < 5.0) {
        colorClass = "var(--color-danger)";
        bgScoreClass = "var(--color-danger-bg)";
      } else if (score < 7.5) {
        colorClass = "var(--color-moderate)";
        bgScoreClass = "var(--color-moderate-bg)";
      }

      const rawCount = parseInt(catData.findings_count, 10);
      const countDisplay = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount : 0;

      card.innerHTML = `
        <div class="cat-header">
          <div class="cat-title">${escapeHtml(catData.category_name)}</div>
          <div class="cat-score-badge" style="color: ${colorClass}; background: ${bgScoreClass};">
            ${scoreBadgeText}
          </div>
        </div>
        <div class="cat-progress-bg">
          <div class="cat-progress-bar" style="width: ${barWidth}%; background: ${colorClass};"></div>
        </div>
        <div class="cat-footer">
          <span>${escapeHtml(catData.summary || "")}</span>
          <span class="findings-count-tag">${escapeHtml(countDisplay)} 指摘</span>
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

    const allFindings = currentScanData.all_findings || currentScanData.findings || [];

    const filtered = allFindings.filter(f => {
      const matchCat = (selectedCat === "ALL" || f.category === selectedCat);
      const matchSev = (selectedSev === "ALL" || (f.severity && f.severity.toUpperCase() === selectedSev));
      return matchCat && matchSev;
    });

    if (filtered.length === 0) {
      const categories = currentScanData.categories || {};
      const requiredKeys = [
        "known_vulnerabilities",
        "secrets",
        "misconfiguration",
        "dependencies",
        "development",
        "cicd",
        "maintenance",
        "source_code"
      ];
      const allEvaluated = requiredKeys.every(k => categories[k] && categories[k].evaluated === true);
      const hasEvaluatedCategory = Object.values(categories).some(c => c && c.evaluated === true);
      const isUnsetOrUnevaluated = currentScanData.status === "評価不能" || !hasEvaluatedCategory;

      if (isUnsetOrUnevaluated) {
        findingsListEl.innerHTML = `<div class="empty-findings">評価可能なスキャンデータが存在しません (未評価)。</div>`;
      } else if (allFindings.length > 0) {
        findingsListEl.innerHTML = `<div class="empty-findings">選択されたフィルター条件に一致する指摘事項 (Findings) はありません。</div>`;
      } else if (allEvaluated) {
        findingsListEl.innerHTML = `<div class="empty-findings">該当する指摘事項 (Findings) はありません。全カテゴリの診断結果は良好です！</div>`;
      } else {
        findingsListEl.innerHTML = `<div class="empty-findings">評価された範囲では指摘事項は検出されませんでしたが、一部のカテゴリは未診断または部分評価となっています。</div>`;
      }
      return;
    }

    const ALLOWED_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    filtered.forEach(f => {
      const card = document.createElement("div");
      let rawSev = (f.severity || "INFO").toUpperCase();
      let sevClass = ALLOWED_SEVS.includes(rawSev) ? rawSev : "INFO";
      card.className = `finding-card sev-${sevClass}`;

      const targetHtml = f.target ? `<div class="finding-target">📄 ${escapeHtml(f.target)} ${f.location ? '(' + escapeHtml(f.location) + ')' : ''}</div>` : '';
      const remedHtml = f.remediation ? `<div class="finding-remediation">💡 対策案内: ${escapeHtml(f.remediation)}</div>` : '';

      card.innerHTML = `
        <div class="finding-meta">
          <span class="sev-tag ${sevClass}">${escapeHtml(rawSev)}</span>
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
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
