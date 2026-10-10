/**
 * PhishLens Web Shield - Popup Script
 * Coordinates active tab analysis queries, UI data binding, and manual rescans.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const stateLoading = document.getElementById('state-loading');
  const stateResults = document.getElementById('state-results');
  const stateError = document.getElementById('state-error');
  const btnRescan = document.getElementById('btn-rescan');

  const errorTitle = document.getElementById('error-title');
  const errorMsg = document.getElementById('error-msg');

  let currentTab = null;

  async function loadTabAndAnalysis() {
    stateLoading.style.display = 'flex';
    stateResults.style.display = 'none';
    stateError.style.display = 'none';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      currentTab = tab;

      if (!tab || !tab.url) {
        showError('No Webpage Detected', 'Please open a valid website tab to run PhishLens analysis.');
        return;
      }

      // Check scheme
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
        showError('Browser Internal Page', 'PhishLens only inspects public HTTP and HTTPS websites.');
        return;
      }

      // Query background service worker
      const response = await chrome.runtime.sendMessage({ action: 'getAnalysis' });

      if (response && response.status === 'SUCCESS' && response.verdict) {
        renderVerdict(response.verdict, response.isBypassed);
      } else {
        // Trigger fresh analysis
        const scanRes = await chrome.runtime.sendMessage({
          action: 'analyzeURL',
          url: tab.url,
          tabId: tab.id
        });

        if (scanRes && scanRes.status === 'SUCCESS' && scanRes.verdict) {
          renderVerdict(scanRes.verdict, false);
        } else {
          showError('Analysis Failed', 'Could not complete analysis for this page.');
        }
      }
    } catch (err) {
      console.error('[PhishLens Popup] Error loading analysis:', err);
      showError('Connection Error', 'Could not communicate with PhishLens background defense service.');
    }
  }

  function renderVerdict(verdict, isBypassed = false) {
    stateLoading.style.display = 'none';
    stateError.style.display = 'none';
    stateResults.style.display = 'block';

    const { category, score, summary, reasons, hostname, url, details } = verdict;

    // 1. Verdict Banner
    const banner = document.getElementById('verdict-banner');
    const vIcon = document.getElementById('verdict-icon');
    const vStatus = document.getElementById('verdict-status');
    const vSummary = document.getElementById('verdict-summary');

    banner.className = 'verdict-banner ' + category.toLowerCase().replace('_', '-');

    if (category === 'LOW_RISK') {
      vIcon.textContent = '✓';
      vStatus.textContent = 'LOW RISK';
    } else if (category === 'SUSPICIOUS') {
      vIcon.textContent = '⚠️';
      vStatus.textContent = isBypassed ? 'SUSPICIOUS (BYPASSED)' : 'SUSPICIOUS';
    } else if (category === 'HIGH_RISK') {
      vIcon.textContent = '🛑';
      vStatus.textContent = isBypassed ? 'HIGH RISK (BYPASSED)' : 'HIGH RISK';
    } else {
      vIcon.textContent = '?';
      vStatus.textContent = 'ANALYSIS ERROR';
    }

    vSummary.textContent = summary || 'Inspection complete.';

    // 2. Risk Meter
    const scoreVal = typeof score === 'number' ? score : 0;
    const scoreText = document.getElementById('meter-score-text');
    const meterFill = document.getElementById('meter-fill');

    scoreText.textContent = `${scoreVal} / 100`;
    meterFill.style.width = `${Math.min(100, Math.max(5, scoreVal))}%`;

    if (scoreVal < 35) {
      meterFill.style.backgroundColor = 'var(--safe-primary)';
    } else if (scoreVal < 70) {
      meterFill.style.backgroundColor = 'var(--warning-primary)';
    } else {
      meterFill.style.backgroundColor = 'var(--danger-primary)';
    }

    // 3. Target Meta
    document.getElementById('target-host').textContent = hostname || 'Unknown';
    try {
      const u = new URL(url);
      document.getElementById('target-transport').textContent = `${u.protocol.toUpperCase()} (Port ${u.port || (u.protocol === 'https:' ? '443' : '80')})`;
    } catch {
      document.getElementById('target-transport').textContent = 'Standard';
    }

    // 4. Engines Grid
    const mlDot = document.getElementById('dot-ml');
    const mlVal = document.getElementById('val-ml');
    if (details?.ml?.available) {
      const probPct = Math.round(details.ml.probability * 100);
      mlVal.textContent = `${probPct}% Prob`;
      mlDot.style.background = probPct >= 50 ? 'var(--danger-primary)' : 'var(--safe-primary)';
    } else {
      mlVal.textContent = 'Offline';
      mlDot.style.background = 'var(--text-muted)';
    }

    const heurVal = document.getElementById('val-heuristics');
    heurVal.textContent = `${details?.heuristic?.score ?? 0}/100`;

    const threatVal = document.getElementById('val-threat');
    const threatDot = document.getElementById('dot-threat');
    const threatVerd = details?.threatIntel?.verdict;
    if (threatVerd === 'KNOWN_MALICIOUS') {
      threatVal.textContent = 'FLAGGED';
      threatDot.style.background = 'var(--danger-primary)';
    } else if (threatVerd === 'SAFE') {
      threatVal.textContent = 'VERIFIED';
      threatDot.style.background = 'var(--safe-primary)';
    } else {
      threatVal.textContent = 'Neutral';
      threatDot.style.background = 'var(--safe-primary)';
    }

    // 5. Reasons List
    const reasonsList = document.getElementById('reasons-list');
    reasonsList.innerHTML = '';

    if (Array.isArray(reasons) && reasons.length > 0) {
      reasons.forEach(r => {
        const li = document.createElement('li');
        
        const tag = document.createElement('span');
        tag.className = `reason-tag ${r.severity || 'INFO'}`;
        tag.textContent = r.severity || 'INFO';

        const text = document.createElement('span');
        text.textContent = `${r.title}: ${r.description}`;

        li.appendChild(tag);
        li.appendChild(text);
        reasonsList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = 'No adverse security flags detected on this URL.';
      reasonsList.appendChild(li);
    }

    // 6. Technical Metrics
    const feats = details?.features || {};
    const dom = details?.domain || {};

    document.getElementById('tech-entropy').textContent = typeof feats.domainEntropy === 'number' ? feats.domainEntropy.toFixed(2) + ' bits' : '-';
    document.getElementById('tech-registrable').textContent = dom.registrableDomain || hostname || '-';
    document.getElementById('tech-subdomains').textContent = typeof feats.numDots === 'number' ? feats.numDots : '-';
    document.getElementById('tech-hyphens').textContent = typeof feats.numHyphens === 'number' ? feats.numHyphens : '-';
    document.getElementById('tech-numeric').textContent = feats.hasIP ? 'Yes (Direct IP)' : (feats.numDigits > 0 ? `${feats.numDigits} digits` : 'No');
    document.getElementById('tech-idn').textContent = hostname.includes('xn--') ? 'Yes (Punycode)' : 'No (Standard ASCII)';
  }

  function showError(title, message) {
    stateLoading.style.display = 'none';
    stateResults.style.display = 'none';
    stateError.style.display = 'block';

    errorTitle.textContent = title;
    errorMsg.textContent = message;
  }

  btnRescan.addEventListener('click', async () => {
    btnRescan.style.transform = 'rotate(180deg)';
    setTimeout(() => { btnRescan.style.transform = ''; }, 300);

    if (currentTab && currentTab.url) {
      stateLoading.style.display = 'flex';
      stateResults.style.display = 'none';

      const scanRes = await chrome.runtime.sendMessage({
        action: 'analyzeURL',
        url: currentTab.url,
        tabId: currentTab.id
      });

      if (scanRes && scanRes.status === 'SUCCESS' && scanRes.verdict) {
        renderVerdict(scanRes.verdict, false);
      }
    }
  });

  // Initial load
  loadTabAndAnalysis();
});
