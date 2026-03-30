const tabData = {};

function getTabData(tabId) {
  if (!tabData[tabId]) {
    tabData[tabId] = {
      url: "",
      domain: "",
      thirdPartyDomains: new Map(),
      cookies: {
        firstParty: [],
        thirdParty: [],
        session: 0,
        persistent: 0,
        total: 0
      },
      superCookies: [],
      cookieSync: [],
      canvasFingerprint: false,
      localStorage: { used: false, keys: [] },
      sessionStorage: { used: false, keys: [] },
      hijackingThreats: [],
      blockedRequests: 0,
      totalRequests: 0,
      privacyScore: 100,
      timestamp: Date.now()
    };
  }
  return tabData[tabId];
}

let userBlocklist = new Set();
let blockingEnabled = true;

browser.storage.local.get(["userBlocklist", "blockingEnabled"]).then(result => {
  if (result.userBlocklist) {
    userBlocklist = new Set(result.userBlocklist);
  }
  if (result.blockingEnabled !== undefined) {
    blockingEnabled = result.blockingEnabled;
  }
});

function extractDomain(url) {
  try {
    const u = new URL(url);
    return u.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function getBaseDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

function isThirdParty(requestDomain, tabDomain) {
  if (!requestDomain || !tabDomain) return false;
  return getBaseDomain(requestDomain) !== getBaseDomain(tabDomain);
}

function isTrackerDomain(domain) {
  const base = getBaseDomain(domain);
  return KNOWN_TRACKERS.has(domain) || KNOWN_TRACKERS.has(base);
}

function shouldBlock(domain) {
  if (!blockingEnabled) return false;
  const base = getBaseDomain(domain);
  return isTrackerDomain(domain) || userBlocklist.has(domain) || userBlocklist.has(base);
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;

    const data = getTabData(details.tabId);
    const requestDomain = extractDomain(details.url);
    data.totalRequests++;

    detectCookieSync(details.url, requestDomain, data);

    detectHijackingInUrl(details.url, data);

    if (data.domain && isThirdParty(requestDomain, data.domain)) {
      const existing = data.thirdPartyDomains.get(requestDomain);
      const tracker = isTrackerDomain(requestDomain);

      if (existing) {
        existing.count++;
      } else {
        data.thirdPartyDomains.set(requestDomain, {
          count: 1,
          blocked: false,
          isTracker: tracker
        });
      }

      if (shouldBlock(requestDomain)) {
        data.blockedRequests++;
        const entry = data.thirdPartyDomains.get(requestDomain);
        if (entry) entry.blocked = true;
        updateBadge(details.tabId, data);
        return { cancel: true };
      }
    }

    updateBadge(details.tabId, data);
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;

    const data = getTabData(details.tabId);
    const requestDomain = extractDomain(details.url);
    const isThird = isThirdParty(requestDomain, data.domain);

    for (const header of details.responseHeaders || []) {
      if (header.name.toLowerCase() === "set-cookie" && header.value) {
        const cookieInfo = parseCookieHeader(header.value, requestDomain, isThird);
        data.cookies.total++;

        if (isThird) {
          data.cookies.thirdParty.push(cookieInfo);
        } else {
          data.cookies.firstParty.push(cookieInfo);
        }

        if (cookieInfo.isSession) {
          data.cookies.session++;
        } else {
          data.cookies.persistent++;
        }

        if (cookieInfo.maxAge > 365 * 24 * 60 * 60) {
          data.superCookies.push({
            domain: requestDomain,
            name: cookieInfo.name,
            maxAge: cookieInfo.maxAge,
            type: "long-lived-cookie"
          });
        }
      }

      if (header.name.toLowerCase() === "etag" && isThird) {
        const etagValue = header.value;
        if (etagValue && etagValue.length > 20) {
          data.superCookies.push({
            domain: requestDomain,
            value: etagValue,
            type: "etag-tracking"
          });
        }
      }

      if (header.name.toLowerCase() === "strict-transport-security" && isThird) {
        const maxAge = parseInt((header.value.match(/max-age=(\d+)/) || [])[1] || "0");
        if (maxAge > 31536000) {
          data.superCookies.push({
            domain: requestDomain,
            maxAge: maxAge,
            type: "hsts-supercookie"
          });
        }
      }
    }

    calculatePrivacyScore(data);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

function parseCookieHeader(cookieStr, domain, isThirdParty) {
  const parts = cookieStr.split(";").map(p => p.trim());
  const [nameVal] = parts;
  const [name, ...valParts] = nameVal.split("=");
  const value = valParts.join("=");

  let maxAge = 0;
  let isSession = true;
  let secure = false;
  let httpOnly = false;
  let sameSite = "none";

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower.startsWith("max-age=")) {
      maxAge = parseInt(lower.split("=")[1]) || 0;
      isSession = false;
    } else if (lower.startsWith("expires=")) {
      const expires = new Date(part.split("=").slice(1).join("="));
      maxAge = Math.floor((expires.getTime() - Date.now()) / 1000);
      isSession = false;
    } else if (lower === "secure") {
      secure = true;
    } else if (lower === "httponly") {
      httpOnly = true;
    } else if (lower.startsWith("samesite=")) {
      sameSite = lower.split("=")[1];
    }
  }

  return {
    name: name?.trim() || "unknown",
    value: value?.substring(0, 50) || "",
    domain,
    isThirdParty,
    isSession,
    maxAge,
    secure,
    httpOnly,
    sameSite
  };
}

function detectCookieSync(url, domain, data) {
  for (const pattern of COOKIE_SYNC_PATTERNS) {
    if (pattern.test(url)) {
      const exists = data.cookieSync.some(s => s.domain === domain);
      if (!exists) {
        data.cookieSync.push({
          domain,
          url: url.substring(0, 200),
          pattern: pattern.toString(),
          timestamp: Date.now()
        });
      }
      break;
    }
  }
}

function detectHijackingInUrl(url, data) {
  const lowerUrl = url.toLowerCase();
  for (const pattern of HIJACKING_PATTERNS) {
    if (lowerUrl.includes(pattern.toLowerCase())) {
      data.hijackingThreats.push({
        type: "suspicious-script",
        url: url.substring(0, 200),
        pattern,
        timestamp: Date.now()
      });
      break;
    }
  }
}

browser.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const data = getTabData(details.tabId);
    data.url = details.url;
    data.domain = extractDomain(details.url);

    if (details.transitionType === "typed" || details.transitionType === "link") {
      tabData[details.tabId] = null;
      const newData = getTabData(details.tabId);
      newData.url = details.url;
      newData.domain = extractDomain(details.url);
    }
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.tab) {
    const data = getTabData(sender.tab.id);

    switch (message.type) {
      case "canvas-fingerprint":
        data.canvasFingerprint = true;
        data.hijackingThreats.push({
          type: "canvas-fingerprint",
          details: message.details,
          timestamp: Date.now()
        });
        calculatePrivacyScore(data);
        break;

      case "localstorage-detected":
        data.localStorage.used = true;
        data.localStorage.keys = message.keys || [];
        calculatePrivacyScore(data);
        break;

      case "sessionstorage-detected":
        data.sessionStorage.used = true;
        data.sessionStorage.keys = message.keys || [];
        break;

      case "hijacking-detected":
        data.hijackingThreats.push({
          type: message.threatType,
          details: message.details,
          timestamp: Date.now()
        });
        calculatePrivacyScore(data);
        break;

      case "supercookie-detected":
        const exists = data.superCookies.some(sc => sc.name === message.name);
        if (!exists) {
          data.superCookies.push({
            domain: message.domain,
            name: message.name,
            maxAge: message.maxAge,
            type: "js-long-lived-cookie"
          });
          calculatePrivacyScore(data);
          updateBadge(sender.tab.id, data);
        }
        break;

      case "js-cookie-set":
        const alreadyCounted = data.cookies.firstParty.some(c => c.name === message.name) ||
                               data.cookies.thirdParty.some(c => c.name === message.name);
        if (!alreadyCounted) {
          const cookieInfo = {
            name: message.name,
            domain: message.domain,
            isThirdParty: false,
            isSession: message.isSession,
            maxAge: message.maxAge,
            source: "js"
          };
          data.cookies.firstParty.push(cookieInfo);
          data.cookies.total++;
          if (message.isSession) {
            data.cookies.session++;
          } else {
            data.cookies.persistent++;
          }
          calculatePrivacyScore(data);
        }
        break;
    }
  }

  switch (message.type) {
    case "get-tab-data":
      browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
        if (tabs[0]) {
          const data = getTabData(tabs[0].id);
          sendResponse(serializeTabData(data));
        }
      });
      return true;

    case "toggle-blocking":
      blockingEnabled = message.enabled;
      browser.storage.local.set({ blockingEnabled });
      sendResponse({ success: true });
      break;

    case "add-to-blocklist":
      userBlocklist.add(message.domain);
      browser.storage.local.set({ userBlocklist: [...userBlocklist] });
      sendResponse({ success: true });
      break;

    case "remove-from-blocklist":
      userBlocklist.delete(message.domain);
      browser.storage.local.set({ userBlocklist: [...userBlocklist] });
      sendResponse({ success: true });
      break;

    case "get-blocklist":
      sendResponse({ blocklist: [...userBlocklist], blockingEnabled });
      break;

    case "clear-blocklist":
      userBlocklist.clear();
      browser.storage.local.set({ userBlocklist: [] });
      sendResponse({ success: true });
      break;
  }
});

function serializeTabData(data) {
  const thirdPartyArray = [];
  data.thirdPartyDomains.forEach((info, domain) => {
    thirdPartyArray.push({ domain, ...info });
  });

  return {
    url: data.url,
    domain: data.domain,
    thirdPartyDomains: thirdPartyArray,
    cookies: data.cookies,
    superCookies: data.superCookies,
    cookieSync: data.cookieSync,
    canvasFingerprint: data.canvasFingerprint,
    localStorage: data.localStorage,
    sessionStorage: data.sessionStorage,
    hijackingThreats: data.hijackingThreats,
    blockedRequests: data.blockedRequests,
    totalRequests: data.totalRequests,
    privacyScore: data.privacyScore,
    timestamp: data.timestamp
  };
}

function calculatePrivacyScore(data) {
  let score = 100;

  const thirdPartyCount = data.thirdPartyDomains.size;
  score -= Math.min(thirdPartyCount * 2, 20);

  let trackerCount = 0;
  data.thirdPartyDomains.forEach(info => {
    if (info.isTracker && !info.blocked) trackerCount++;
  });
  score -= Math.min(trackerCount * 3, 25);

  score -= Math.min(data.cookies.thirdParty.length, 15);

  score -= Math.min(data.superCookies.length * 5, 15);

  score -= Math.min(data.cookieSync.length * 5, 10);

  if (data.canvasFingerprint) score -= 10;

  if (data.localStorage.used && data.localStorage.keys.length > 5) score -= 5;

  const hijackCount = data.hijackingThreats.filter(t => t.type !== "canvas-fingerprint").length;
  score -= Math.min(hijackCount * 10, 15);

  data.privacyScore = Math.max(0, Math.min(100, score));
}

function updateBadge(tabId, data) {
  const trackerCount = data.blockedRequests;
  const color = data.privacyScore >= 70 ? "#22c55e" :
                data.privacyScore >= 40 ? "#f59e0b" : "#ef4444";

  browser.browserAction.setBadgeText({
    text: trackerCount > 0 ? String(trackerCount) : "",
    tabId
  });
  browser.browserAction.setBadgeBackgroundColor({ color, tabId });
}