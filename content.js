// PhishLens Web Shield - Content Script
// Injects warning banners into potentially unsafe websites
// Shows safe notifications for legitimate websites

let warningBanner = null;
let safeNotification = null;
let safeNotificationTimer = null;

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showWarning') {
    if (!request.safe && request.score >= 40) {
      showWarningBanner(request.score, request.reason);
      removeSafeNotification(); // Remove safe notification if showing
    } else if (request.safe) {
      removeWarningBanner();
      showSafeNotification(); // Show safe notification
    } else {
      removeWarningBanner();
      removeSafeNotification();
    }
  }
});

// Create and show warning banner
function showWarningBanner(score, reason) {
  // Remove existing banner if any
  removeWarningBanner();

  // Create banner element
  warningBanner = document.createElement('div');
  warningBanner.id = 'phishlens-warning-banner';
  
  const severity = score >= 75 ? 'critical' : 'warning';
  const icon = score >= 75 ? '🛑' : '⚠️';
  
  warningBanner.innerHTML = `
    <div class="phishlens-banner-content">
      <div class="phishlens-icon">${icon}</div>
      <div class="phishlens-message">
        <strong>PhishLens Web Shield Alert</strong>
        <p>🔴 UNSAFE: This website appears suspicious or phishing (Risk Score: ${score}/100)</p>
        <p class="phishlens-reason">${reason}</p>
      </div>
      <button class="phishlens-close" id="phishlens-close-btn">×</button>
    </div>
  `;

  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    #phishlens-warning-banner {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: ${severity === 'critical' ? 'linear-gradient(135deg, #c0392b 0%, #e74c3c 100%)' : 'linear-gradient(135deg, #e67e22 0%, #f39c12 100%)'};
      color: white;
      padding: 15px 20px;
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
      animation: slideDown 0.3s ease-out;
    }

    @keyframes slideDown {
      from {
        transform: translateY(-100%);
        opacity: 0;
      }
      to {
        transform: translateY(0);
        opacity: 1;
      }
    }

    .phishlens-banner-content {
      display: flex;
      align-items: center;
      max-width: 1200px;
      margin: 0 auto;
      gap: 15px;
    }

    .phishlens-icon {
      font-size: 32px;
      flex-shrink: 0;
    }

    .phishlens-message {
      flex-grow: 1;
    }

    .phishlens-message strong {
      display: block;
      font-size: 16px;
      margin-bottom: 5px;
    }

    .phishlens-message p {
      margin: 3px 0;
      font-size: 14px;
      line-height: 1.4;
    }

    .phishlens-reason {
      font-size: 13px !important;
      opacity: 0.95;
      font-style: italic;
    }

    .phishlens-close {
      background: rgba(255,255,255,0.2);
      border: 2px solid rgba(255,255,255,0.5);
      color: white;
      font-size: 28px;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
      flex-shrink: 0;
      padding: 0;
      line-height: 1;
    }

    .phishlens-close:hover {
      background: rgba(255,255,255,0.3);
      transform: scale(1.1);
    }

    body {
      padding-top: 120px !important;
    }
  `;

  // Insert into page
  if (document.head) {
    document.head.appendChild(style);
  }
  
  if (document.body) {
    document.body.insertBefore(warningBanner, document.body.firstChild);
  } else {
    // Page not fully loaded yet, wait
    document.addEventListener('DOMContentLoaded', () => {
      if (document.body) {
        document.body.insertBefore(warningBanner, document.body.firstChild);
      }
    });
  }

  // Add close button listener
  setTimeout(() => {
    const closeBtn = document.getElementById('phishlens-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', removeWarningBanner);
    }
  }, 100);
}

// Remove warning banner
function removeWarningBanner() {
  if (warningBanner && warningBanner.parentNode) {
    warningBanner.remove();
    warningBanner = null;
  }
  
  // Reset body padding
  if (document.body) {
    document.body.style.paddingTop = '';
  }
}

// Show safe notification
function showSafeNotification() {
  // Remove existing notification if any
  removeSafeNotification();
  
  // Clear any existing timer
  if (safeNotificationTimer) {
    clearTimeout(safeNotificationTimer);
  }

  // Create notification element
  safeNotification = document.createElement('div');
  safeNotification.id = 'phishlens-safe-notification';
  
  safeNotification.innerHTML = `
    <div class="phishlens-safe-content">
      <div class="phishlens-safe-icon">✓</div>
      <div class="phishlens-safe-text">Safe URL</div>
    </div>
  `;

  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    #phishlens-safe-notification {
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
      color: white;
      padding: 15px 25px;
      border-radius: 50px;
      z-index: 2147483647;
      box-shadow: 0 4px 20px rgba(17, 153, 142, 0.4);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
      animation: slideInRight 0.5s ease-out, fadeOut 0.5s ease-out 4.5s;
      pointer-events: none;
    }

    @keyframes slideInRight {
      from {
        transform: translateX(400px);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    @keyframes fadeOut {
      from {
        opacity: 1;
      }
      to {
        opacity: 0;
      }
    }

    .phishlens-safe-content {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .phishlens-safe-icon {
      font-size: 24px;
      font-weight: bold;
      background: white;
      color: #11998e;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .phishlens-safe-text {
      font-size: 16px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
  `;

  // Insert into page
  if (document.head) {
    document.head.appendChild(style);
  }
  
  if (document.body) {
    document.body.appendChild(safeNotification);
  } else {
    // Page not fully loaded yet, wait
    document.addEventListener('DOMContentLoaded', () => {
      if (document.body && safeNotification) {
        document.body.appendChild(safeNotification);
      }
    });
  }

  // Auto-remove after 5 seconds
  safeNotificationTimer = setTimeout(() => {
    removeSafeNotification();
  }, 5000);
}

// Remove safe notification
function removeSafeNotification() {
  if (safeNotificationTimer) {
    clearTimeout(safeNotificationTimer);
    safeNotificationTimer = null;
  }
  
  if (safeNotification && safeNotification.parentNode) {
    safeNotification.remove();
    safeNotification = null;
  }
}

// Initialize
console.log('PhishLens Web Shield: Content script loaded');
