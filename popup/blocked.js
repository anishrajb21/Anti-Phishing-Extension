/**
 * PhishLens Blocked Interstitial Page Script
 * Safely renders warning details and provides controlled bypass authorization.
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const rawTargetUrl = urlParams.get('url') || '';
  const scoreParam = urlParams.get('score');
  const reasonParam = urlParams.get('reason');

  const targetUrlEl = document.getElementById('target-url');
  const scorePillEl = document.getElementById('score-pill');
  const reasonsListEl = document.getElementById('reasons-list');
  const btnBack = document.getElementById('btn-back');
  const btnProceed = document.getElementById('btn-proceed');

  // Display URL safely
  if (rawTargetUrl) {
    try {
      const parsed = new URL(rawTargetUrl);
      targetUrlEl.textContent = `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;
    } catch {
      targetUrlEl.textContent = rawTargetUrl;
    }
  } else {
    targetUrlEl.textContent = 'Unknown destination';
  }

  // Display Score
  if (scoreParam) {
    scorePillEl.textContent = `Risk: ${scoreParam}/100`;
  }

  // Display Reasons safely using textContent
  if (reasonParam) {
    reasonsListEl.innerHTML = '';
    const reasons = reasonParam.split('. ').filter(Boolean);
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r.trim() + (r.endsWith('.') ? '' : '.');
      reasonsListEl.appendChild(li);
    });
  }

  // Action: Return to Safety
  btnBack.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://www.google.com';
    }
  });

  // Action: Proceed Anyway with session bypass authorization
  btnProceed.addEventListener('click', async () => {
    if (!rawTargetUrl) return;

    const confirmed = window.confirm(
      '⚠️ SECURITY WARNING: Are you sure you want to visit this website?\n\n' +
      'PhishLens flagged this destination as high-risk. Phishing websites can steal your passwords, credit cards, or personal accounts.\n\n' +
      'Click OK to proceed at your own risk.'
    );

    if (!confirmed) return;

    try {
      btnProceed.textContent = 'Authorizing bypass...';
      btnProceed.disabled = true;

      // Request background service worker to grant a temporary session bypass for this URL
      const response = await chrome.runtime.sendMessage({
        action: 'grantBypass',
        url: rawTargetUrl
      });

      if (response && response.success) {
        // Safe navigation without infinite redirect loop
        window.location.replace(rawTargetUrl);
      } else {
        // Fallback navigation
        window.location.href = rawTargetUrl;
      }
    } catch (err) {
      console.error('[PhishLens] Error requesting bypass:', err);
      window.location.href = rawTargetUrl;
    }
  });
});
