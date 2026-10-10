/**
 * PhishLens Web Shield - Hardened Content Script
 * Displays accessible, sanitized warning banners on suspicious pages.
 * Never injects intrusive banners onto safe pages, and avoids unsafe innerHTML operations.
 */

let activeBanner = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showSuspiciousNotice') {
    // Only display warning if site is suspicious
    showSuspiciousBanner(request.score, request.summary, request.reasons);
  }
});

/**
 * Creates and injects a sanitized floating warning banner into the DOM.
 * @param {number} score
 * @param {string} summary
 * @param {Array<{ title: string, description: string }>} reasons
 */
function showSuspiciousBanner(score, summary, reasons = []) {
  if (activeBanner) return; // Prevent duplicate banners

  // Container
  const banner = document.createElement('aside');
  banner.id = 'phishlens-suspicious-alert';
  banner.setAttribute('role', 'alert');
  banner.setAttribute('aria-live', 'assertive');

  // Styling via shadow DOM or isolated styles
  const style = document.createElement('style');
  style.textContent = `
    #phishlens-suspicious-alert {
      position: fixed;
      top: 16px;
      right: 16px;
      max-width: 420px;
      width: calc(100vw - 32px);
      background: #1e293b;
      color: #f8fafc;
      border: 1px solid #f59e0b;
      border-left: 6px solid #f59e0b;
      border-radius: 8px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      padding: 14px 16px;
      animation: phishlensSlideIn 0.3s ease-out;
    }

    @keyframes phishlensSlideIn {
      from { transform: translateX(120%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }

    .phishlens-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }

    .phishlens-title-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .phishlens-icon {
      font-size: 18px;
    }

    .phishlens-title {
      font-weight: 700;
      color: #f59e0b;
      font-size: 14px;
      margin: 0;
    }

    .phishlens-badge {
      background: rgba(245, 158, 11, 0.15);
      color: #f59e0b;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }

    .phishlens-body {
      margin-bottom: 10px;
      color: #cbd5e1;
    }

    .phishlens-reasons {
      margin: 6px 0 0 0;
      padding-left: 18px;
      color: #94a3b8;
      font-size: 12px;
    }

    .phishlens-reasons li {
      margin-bottom: 3px;
    }

    .phishlens-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      padding-top: 8px;
    }

    .phishlens-btn {
      background: transparent;
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #e2e8f0;
      padding: 4px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s;
    }

    .phishlens-btn:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #ffffff;
    }

    .phishlens-close-icon {
      background: none;
      border: none;
      color: #94a3b8;
      font-size: 18px;
      cursor: pointer;
      padding: 0 4px;
      line-height: 1;
    }

    .phishlens-close-icon:hover {
      color: #ffffff;
    }
  `;

  // Safe DOM Construction (No innerHTML)
  const header = document.createElement('div');
  header.className = 'phishlens-header';

  const titleGroup = document.createElement('div');
  titleGroup.className = 'phishlens-title-group';

  const icon = document.createElement('span');
  icon.className = 'phishlens-icon';
  icon.textContent = '⚠️';

  const title = document.createElement('h4');
  title.className = 'phishlens-title';
  title.textContent = 'PhishLens Security Alert';

  const scoreBadge = document.createElement('span');
  scoreBadge.className = 'phishlens-badge';
  scoreBadge.textContent = `Risk: ${score}/100`;

  titleGroup.appendChild(icon);
  titleGroup.appendChild(title);
  titleGroup.appendChild(scoreBadge);

  const closeIcon = document.createElement('button');
  closeIcon.className = 'phishlens-close-icon';
  closeIcon.textContent = '×';
  closeIcon.setAttribute('aria-label', 'Close security warning');
  closeIcon.addEventListener('click', dismissBanner);

  header.appendChild(titleGroup);
  header.appendChild(closeIcon);

  // Body content
  const body = document.createElement('div');
  body.className = 'phishlens-body';
  body.textContent = summary || 'This website displays anomalous security indicators.';

  // Reasons list (if available)
  if (Array.isArray(reasons) && reasons.length > 0) {
    const list = document.createElement('ul');
    list.className = 'phishlens-reasons';
    reasons.slice(0, 3).forEach(r => {
      const item = document.createElement('li');
      item.textContent = r.title || r;
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  // Footer Actions
  const actions = document.createElement('div');
  actions.className = 'phishlens-actions';

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'phishlens-btn';
  dismissBtn.textContent = 'I understand';
  dismissBtn.addEventListener('click', dismissBanner);

  actions.appendChild(dismissBtn);

  // Assemble
  banner.appendChild(header);
  banner.appendChild(body);
  banner.appendChild(actions);

  const container = document.createElement('div');
  container.appendChild(style);
  container.appendChild(banner);

  activeBanner = container;

  const target = document.body || document.documentElement;
  if (target) {
    target.appendChild(container);
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      (document.body || document.documentElement).appendChild(container);
    });
  }
}

function dismissBanner() {
  if (activeBanner && activeBanner.parentNode) {
    activeBanner.remove();
    activeBanner = null;
  }
}
