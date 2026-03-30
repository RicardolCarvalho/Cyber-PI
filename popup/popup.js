document.addEventListener("DOMContentLoaded", () => {
  loadData();
});

function loadData() {
  browser.runtime.sendMessage({ type: "get-tab-data" }).then(data => {
    if (data) {
      renderData(data);
    }
  }).catch(() => {
    document.getElementById("current-domain").textContent = "Erro ao carregar dados";
  });
}

function renderData(data) {
  document.getElementById("current-domain").textContent = data.domain || "—";

  renderScore(data.privacyScore);

  document.getElementById("stat-blocked").textContent = data.blockedRequests;
  document.getElementById("stat-third-party").textContent = (data.thirdPartyDomains || []).length;
  document.getElementById("stat-cookies").textContent = data.cookies.total;

  const threatCount = (data.hijackingThreats || []).length +
    (data.canvasFingerprint ? 1 : 0) +
    (data.superCookies || []).length;
  document.getElementById("stat-threats").textContent = threatCount;

  renderThirdPartyDomains(data.thirdPartyDomains || []);
  renderCanvasFingerprint(data.canvasFingerprint);
  renderCookieSync(data.cookieSync || []);
  renderStorage(data.localStorage, data.sessionStorage);
  renderHijacking(data.hijackingThreats || []);
  renderSupercookies(data.superCookies || []);
}

function renderScore(score) {
  const circle = document.getElementById("score-circle");
  const value = document.getElementById("score-value");
  const label = document.getElementById("score-label");

  const circumference = 2 * Math.PI * 52; // r=52
  const offset = circumference - (score / 100) * circumference;

  let color, labelText;
  if (score >= 70) {
    color = "#22c55e";
    labelText = "Boa Privacidade";
  } else if (score >= 40) {
    color = "#f59e0b";
    labelText = "Privacidade Moderada";
  } else {
    color = "#ef4444";
    labelText = "Privacidade Comprometida";
  }

  circle.style.stroke = color;
  circle.style.strokeDashoffset = offset;
  value.textContent = score;
  value.style.color = color;
  label.textContent = labelText;
}

function renderThirdPartyDomains(domains) {
  const container = document.getElementById("third-party-list");
  const badge = document.getElementById("badge-third-party");
  badge.textContent = domains.length;

  if (domains.length === 0) {
    container.innerHTML = '<div class="empty-state">Nenhum domínio de terceiros detectado</div>';
    badge.className = "badge safe";
    return;
  }

  badge.className = domains.length > 5 ? "badge danger" : "badge warning";

  domains.sort((a, b) => {
    if (a.isTracker !== b.isTracker) return b.isTracker - a.isTracker;
    return b.count - a.count;
  });

  container.innerHTML = domains.map(d => `
    <div class="domain-item">
      <span class="domain-name" title="${d.domain}">${d.domain}</span>
      <div class="domain-meta">
        <span class="domain-count">${d.count}×</span>
        ${d.isTracker ? '<span class="domain-tag tracker">Tracker</span>' : ''}
        ${d.blocked ? '<span class="domain-tag blocked">Bloqueado</span>' :
      `<button class="btn-block" data-domain="${d.domain}">Bloquear</button>`}
      </div>
    </div>
  `).join("");

  container.querySelectorAll(".btn-block").forEach(btn => {
    btn.addEventListener("click", () => {
      const domain = btn.dataset.domain;
      browser.runtime.sendMessage({ type: "add-to-blocklist", domain }).then(() => {
        loadData();
      });
    });
  });
}

function renderCanvasFingerprint(detected) {
  const alert = document.getElementById("canvas-alert");
  const badge = document.getElementById("badge-canvas");

  if (detected) {
    alert.style.display = "flex";
    badge.textContent = "Detectado";
    badge.className = "badge danger";
  } else {
    alert.style.display = "none";
    badge.textContent = "Não detectado";
    badge.className = "badge safe";
  }
}

function renderCookieSync(syncList) {
  const container = document.getElementById("cookie-sync-list");
  const badge = document.getElementById("badge-sync");
  badge.textContent = syncList.length;

  if (syncList.length === 0) {
    container.innerHTML = '<div class="empty-state">Nenhum sincronismo de cookies detectado</div>';
    badge.className = "badge safe";
    return;
  }

  badge.className = "badge danger";

  container.innerHTML = syncList.map(s => `
    <div class="domain-item">
      <span class="domain-name" title="${s.url}">${s.domain}</span>
      <span class="domain-tag tracker">Sync</span>
    </div>
  `).join("");
}

function renderStorage(local, session) {
  const localStatus = document.getElementById("localstorage-status");
  const sessionStatus = document.getElementById("sessionstorage-status");

  if (local && local.used) {
    localStatus.textContent = `${local.keys.length} chave(s)`;
    localStatus.className = "storage-status active";
  } else {
    localStatus.textContent = "Não utilizado";
    localStatus.className = "storage-status inactive";
  }

  if (session && session.used) {
    sessionStatus.textContent = `${session.keys.length} chave(s)`;
    sessionStatus.className = "storage-status active";
  } else {
    sessionStatus.textContent = "Não utilizado";
    sessionStatus.className = "storage-status inactive";
  }
}

function renderHijacking(threats) {
  const container = document.getElementById("hijacking-list");
  const badge = document.getElementById("badge-hijacking");
  const nonCanvasThreats = threats.filter(t => t.type !== "canvas-fingerprint");
  badge.textContent = nonCanvasThreats.length;

  if (nonCanvasThreats.length === 0) {
    container.innerHTML = '<div class="empty-state">Nenhuma ameaça detectada</div>';
    badge.className = "badge safe";
    return;
  }

  badge.className = "badge danger";

  container.innerHTML = nonCanvasThreats.map(t => `
    <div class="domain-item">
      <span class="domain-name" title="${t.details || ''}">${t.type}: ${(t.details || '').substring(0, 80)}</span>
    </div>
  `).join("");
}

function renderSupercookies(superCookies) {
  const container = document.getElementById("supercookie-list");
  const badge = document.getElementById("badge-supercookies");
  badge.textContent = superCookies.length;

  if (superCookies.length === 0) {
    container.innerHTML = '<div class="empty-state">Nenhum supercookie detectado</div>';
    badge.className = "badge safe";
    return;
  }

  badge.className = "badge danger";

  container.innerHTML = superCookies.map(sc => `
    <div class="domain-item">
      <span class="domain-name">${sc.domain}</span>
      <span class="domain-tag tracker">${sc.type}</span>
    </div>
  `).join("");
}

