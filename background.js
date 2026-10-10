/**
 * PhishLens Web Shield - Background Service Worker (Manifest V3)
 * Orchestrates navigation lifecycle, on-device ML inference, heuristic scoring, and session bypass.
 */

import { RiskScorer } from './src/engine/riskScorer.js';
import { MLEngine } from './src/engine/mlEngine.js';
import { ThreatIntelManager, LocalThreatIntelProvider } from './src/engine/threatIntelligence.js';
import { SessionManager } from './src/engine/sessionManager.js';

// Instantiate Core Engines
const mlEngine = new MLEngine();
const threatIntelManager = new ThreatIntelManager([new LocalThreatIntelProvider()]);
const sessionManager = new SessionManager({
  cacheTtlMs: 5 * 60 * 1000,   // 5 minutes cache
  bypassTtlMs: 10 * 60 * 1000  // 10 minutes user bypass
});

const riskScorer = new RiskScorer({
  mlEngine,
  threatIntelManager,
  suspiciousThreshold: 35,
  highRiskThreshold: 70
});

// Promise to ensure model is fully loaded before processing requests
let modelInitPromise = null;

async function initModel() {
  try {
    const url = chrome.runtime.getURL('model/phishing_model.json');
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to load model file: HTTP ${response.status}`);
    }
    const modelData = await response.json();
    mlEngine.loadModel(modelData);
    console.log('[PhishLens] On-device ML model loaded successfully (v' + modelData.version + ')');
  } catch (err) {
    console.error('[PhishLens] Failed to load on-device ML model:', err);
  }
}

modelInitPromise = initModel();

/**
 * Updates extension action badge for a tab.
 * @param {number} tabId
 * @param {'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'ERROR' | 'BYPASS'} status
 * @param {number | null} score
 */
function updateBadge(tabId, status, score) {
  if (!tabId || tabId < 0) return;

  let text = '';
  let color = '#6c757d';

  switch (status) {
    case 'LOW_RISK':
      text = '✓';
      color = '#10b981'; // Green
      break;
    case 'SUSPICIOUS':
      text = score ? String(score) : '!';
      color = '#f59e0b'; // Amber
      break;
    case 'HIGH_RISK':
      text = '!';
      color = '#ef4444'; // Red
      break;
    case 'BYPASS':
      text = '⚠️';
      color = '#6366f1'; // Indigo (user accepted risk)
      break;
    case 'ERROR':
      text = '?';
      color = '#6b7280'; // Slate
      break;
    default:
      text = '';
      color = '#6b7280';
  }

  try {
    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text, tabId });
  } catch (err) {
    // Tab might have been closed
  }
}

/**
 * Updates DeclarativeNetRequest dynamic rules for a high-risk domain.
 * @param {string} hostname
 */
async function addDnrBlockRule(hostname) {
  if (!chrome.declarativeNetRequest || !hostname) return;
  try {
    const ruleId = Math.abs(hashCode(hostname)) % 10000 + 1;
    const rule = {
      id: ruleId,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: {
          url: chrome.runtime.getURL('popup/blocked.html') + '?url=' + encodeURIComponent('https://' + hostname) + '&score=95&reason=Threat%20Intelligence%20Block'
        }
      },
      condition: {
        urlFilter: `||${hostname}^`,
        resourceTypes: ['main_frame']
      }
    };
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId],
      addRules: [rule]
    });
  } catch (err) {
    console.warn('[PhishLens] DNR dynamic rule update skipped:', err.message);
  }
}

/**
 * Removes DeclarativeNetRequest dynamic rule when user authorizes bypass.
 * @param {string} hostname
 */
async function removeDnrBlockRule(hostname) {
  if (!chrome.declarativeNetRequest || !hostname) return;
  try {
    const ruleId = Math.abs(hashCode(hostname)) % 10000 + 1;
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId]
    });
  } catch (err) {
    // Ignore DNR cleanup error
  }
}

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

// -------------------------------------------------------------
// Navigation Event Handlers
// -------------------------------------------------------------

// Pre-Navigation Interception
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only monitor main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    return;
  }

  await modelInitPromise;

  // Check if tab has an active user-authorized bypass for this URL
  if (sessionManager.isBypassed(details.tabId, url)) {
    console.log('[PhishLens] User bypass active for:', url);
    updateBadge(details.tabId, 'BYPASS', null);
    return;
  }

  // Check cache first to prevent duplicate analysis on navigation redirect chains
  let verdict = sessionManager.getAnalysis(details.tabId, url);
  if (!verdict) {
    verdict = await riskScorer.analyze(url);
    sessionManager.setAnalysis(details.tabId, url, verdict);
  }

  updateBadge(details.tabId, verdict.category, verdict.score);

  // If High Risk, redirect to the blocked warning page
  if (verdict.category === 'HIGH_RISK') {
    console.warn('[PhishLens] Blocking dangerous URL:', url, 'Score:', verdict.score);

    // Register DNR dynamic rule for host if threat intelligence confirmed
    if (verdict.details?.threatIntel?.verdict === 'KNOWN_MALICIOUS') {
      await addDnrBlockRule(verdict.hostname);
    }

    const firstReason = verdict.reasons?.[0]?.title || 'Multiple high-risk indicators detected';
    const redirectUrl = chrome.runtime.getURL('popup/blocked.html') +
      '?url=' + encodeURIComponent(url) +
      '&score=' + encodeURIComponent(String(verdict.score)) +
      '&reason=' + encodeURIComponent(firstReason);

    chrome.tabs.update(details.tabId, { url: redirectUrl });
  }
});

// Post-Navigation Commit (Badge synchronization and gentle warning banner if suspicious)
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    return;
  }

  await modelInitPromise;

  if (sessionManager.isBypassed(details.tabId, url)) {
    updateBadge(details.tabId, 'BYPASS', null);
    return;
  }

  let verdict = sessionManager.getAnalysis(details.tabId, url);
  if (!verdict) {
    verdict = await riskScorer.analyze(url);
    sessionManager.setAnalysis(details.tabId, url, verdict);
  }

  updateBadge(details.tabId, verdict.category, verdict.score);

  // If SUSPICIOUS (not blocked, but noteworthy), send subtle notification to content script
  if (verdict.category === 'SUSPICIOUS') {
    try {
      await chrome.tabs.sendMessage(details.tabId, {
        action: 'showSuspiciousNotice',
        score: verdict.score,
        summary: verdict.summary,
        reasons: verdict.reasons
      });
    } catch {
      // Content script may not have connected yet; benign
    }
  }
});

// Clean up tab state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  sessionManager.clearTab(tabId);
});

// -------------------------------------------------------------
// Message Routing (Popup & Content Script Communication)
// -------------------------------------------------------------

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Request 1: Get cached analysis for current active tab
  if (request.action === 'getAnalysis') {
    (async () => {
      await modelInitPromise;
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        if (!tabs || !tabs[0] || !tabs[0].url) {
          sendResponse({ status: 'ERROR', error: 'No active tab found' });
          return;
        }

        const tab = tabs[0];
        let verdict = sessionManager.getAnalysis(tab.id, tab.url);
        if (!verdict) {
          verdict = await riskScorer.analyze(tab.url);
          sessionManager.setAnalysis(tab.id, tab.url, verdict);
          updateBadge(tab.id, verdict.category, verdict.score);
        }

        sendResponse({
          status: 'SUCCESS',
          verdict,
          isBypassed: sessionManager.isBypassed(tab.id, tab.url)
        });
      });
    })();
    return true; // Keep channel open for async response
  }

  // Request 2: Re-analyze a specific URL on demand (manual re-scan)
  if (request.action === 'analyzeURL') {
    (async () => {
      await modelInitPromise;
      const targetUrl = request.url;
      const tabId = request.tabId;

      const verdict = await riskScorer.analyze(targetUrl);
      if (tabId) {
        sessionManager.setAnalysis(tabId, targetUrl, verdict);
        updateBadge(tabId, verdict.category, verdict.score);
      }

      sendResponse({
        status: 'SUCCESS',
        verdict
      });
    })();
    return true;
  }

  // Request 3: User authorized bypass ("Proceed Anyway" from blocked page)
  if (request.action === 'grantBypass') {
    (async () => {
      const targetUrl = request.url;
      const tabId = sender.tab ? sender.tab.id : request.tabId;

      if (tabId && targetUrl) {
        sessionManager.grantBypass(tabId, targetUrl);

        try {
          const parsed = new URL(targetUrl);
          await removeDnrBlockRule(parsed.hostname);
        } catch {
          // Ignore URL parse error
        }

        updateBadge(tabId, 'BYPASS', null);
        console.log(`[PhishLens] Bypass granted for tab ${tabId} on ${targetUrl}`);
        sendResponse({ success: true, url: targetUrl });
      } else {
        sendResponse({ success: false, error: 'Missing tabId or target URL' });
      }
    })();
    return true;
  }

  // Request 4: Threat Intelligence Status
  if (request.action === 'getThreatIntelStatus') {
    sendResponse({
      status: 'ACTIVE',
      providers: ['Local Curated Threat Feed'],
      cacheSize: threatIntelManager.cache.cache.size
    });
    return false;
  }
});

// Periodic cache pruning
setInterval(() => {
  sessionManager.prune();
}, 60000);

console.log('[PhishLens] Background service worker initialization complete.');
