// PhishLens Blocked Page Script
// Handles the warning page when unsafe sites are blocked

document.addEventListener('DOMContentLoaded', () => {
  // Parse URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url');
  const score = urlParams.get('score');
  const reason = urlParams.get('reason');

  // Display blocked URL
  if (blockedUrl) {
    document.getElementById('blocked-url').textContent = blockedUrl;
  }

  // Display risk score
  if (score) {
    document.getElementById('score-display').textContent = score;
  }

  // Display reasons
  if (reason) {
    const reasonsList = document.getElementById('risk-list');
    reasonsList.innerHTML = '';
    
    // Split reasons by period and create list items
    const reasons = reason.split('. ').filter(r => r.trim());
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r.trim() + (r.endsWith('.') ? '' : '.');
      reasonsList.appendChild(li);
    });
  }

  // Go Back button
  document.getElementById('go-back').addEventListener('click', () => {
    // Navigate to a safe page
    window.location.href = 'https://www.google.com';
  });

  // Proceed Anyway button (with confirmation)
  document.getElementById('proceed-anyway').addEventListener('click', () => {
    const confirmed = confirm(
      '⚠️ WARNING: You are about to visit a potentially dangerous website!\n\n' +
      'This site has been flagged as suspicious and may:\n' +
      '• Steal your passwords and personal information\n' +
      '• Install malware on your device\n' +
      '• Trick you into revealing financial data\n\n' +
      'Are you ABSOLUTELY SURE you want to proceed?'
    );

    if (confirmed) {
      const doubleConfirm = confirm(
        '⚠️ FINAL WARNING!\n\n' +
        'PhishLens strongly recommends NOT visiting this site.\n\n' +
        'Risk Score: ' + score + '/100\n\n' +
        'Click OK only if you fully understand the risks and trust this website.'
      );

      if (doubleConfirm && blockedUrl) {
        // Allow user to proceed at their own risk
        window.location.href = blockedUrl;
      }
    }
  });
});
