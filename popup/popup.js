// PhishLens Web Shield - Popup Script
// Displays detailed analysis of current webpage

document.addEventListener('DOMContentLoaded', async () => {
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const error = document.getElementById('error');

  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      showError();
      return;
    }

    // Check if it's a chrome:// or extension page
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
      error.querySelector('p').textContent = '⚠️ Cannot Analyze This Page';
      error.querySelector('.error-detail').textContent = 'Analysis only works on regular websites (HTTP/HTTPS).';
      showError();
      return;
    }

    // Function to get or trigger analysis
    const getAnalysis = async () => {
      const response = await chrome.runtime.sendMessage({ action: 'getAnalysis' });
      
      if (response && response.url === tab.url) {
        return response;
      }
      
      // If no response or URL mismatch, trigger analysis via background
      console.log('PhishLens Popup: Triggering fresh analysis for', tab.url);
      
      // Send message to background to analyze this specific URL
      const triggerResponse = await chrome.runtime.sendMessage({ 
        action: 'analyzeURL', 
        url: tab.url,
        tabId: tab.id
      });
      
      if (triggerResponse) {
        return triggerResponse;
      }
      
      return null;
    };

    // Try to get analysis
    let analysisData = await getAnalysis();
    
    // If still no data, wait a bit and retry
    if (!analysisData) {
      loading.querySelector('p').textContent = 'Analyzing website...';
      await new Promise(resolve => setTimeout(resolve, 500));
      analysisData = await getAnalysis();
    }
    
    // Final retry
    if (!analysisData) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      analysisData = await getAnalysis();
    }

    if (!analysisData) {
      showError();
      return;
    }

    // Hide loading, show results
    loading.style.display = 'none';
    results.style.display = 'block';

    // Populate UI with analysis data
    displayResults(analysisData);
  } catch (err) {
    console.error('Error loading analysis:', err);
    showError();
  }
});

function displayResults(data) {
  const { safe, score, reason, url, features, mlScore, heuristicScore, domainAge } = data;

  // Status Banner
  const statusBanner = document.getElementById('status-banner');
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusMessage = document.getElementById('status-message');

  if (safe) {
    statusBanner.className = 'status-banner safe';
    statusIcon.textContent = '🟢';
    statusTitle.textContent = 'SAFE';
    statusMessage.textContent = 'This website looks legitimate.';
  } else {
    statusBanner.className = 'status-banner unsafe';
    statusIcon.textContent = '🔴';
    statusTitle.textContent = 'UNSAFE';
    statusMessage.textContent = 'This website appears suspicious or phishing.';
  }

  // Risk Score
  const scoreValue = document.getElementById('score-value');
  const meterFill = document.getElementById('meter-fill');

  scoreValue.textContent = `${score}/100`;
  meterFill.style.width = `${score}%`;

  if (score < 30) {
    meterFill.className = 'meter-fill safe';
  } else if (score < 60) {
    meterFill.className = 'meter-fill moderate';
  } else {
    meterFill.className = 'meter-fill unsafe';
  }

  // URL
  try {
    const urlObj = new URL(url);
    document.getElementById('url-value').textContent = urlObj.hostname;
  } catch (e) {
    document.getElementById('url-value').textContent = 'Invalid URL';
  }

  // SSL/HTTPS
  const sslValue = document.getElementById('ssl-value');
  if (features && features.hasHTTPS) {
    sslValue.textContent = '✅ Valid HTTPS';
    sslValue.style.color = '#28a745';
  } else {
    sslValue.textContent = '⚠️ No HTTPS';
    sslValue.style.color = '#dc3545';
  }

  // Domain Age
  const domainAgeValue = document.getElementById('domain-age-value');
  if (domainAge !== null && domainAge !== undefined) {
    if (domainAge < 30) {
      domainAgeValue.textContent = `${domainAge} days (Very New ⚠️)`;
      domainAgeValue.style.color = '#dc3545';
    } else if (domainAge < 365) {
      domainAgeValue.textContent = `${domainAge} days`;
      domainAgeValue.style.color = '#f39c12';
    } else {
      const years = Math.floor(domainAge / 365);
      domainAgeValue.textContent = `~${years} year${years > 1 ? 's' : ''} ✅`;
      domainAgeValue.style.color = '#28a745';
    }
  } else {
    domainAgeValue.textContent = 'Not available';
    domainAgeValue.style.color = '#999';
  }

  // ML Score
  document.getElementById('ml-score-value').textContent = mlScore !== undefined ? `${mlScore}/100` : 'N/A';

  // Heuristic Score
  document.getElementById('heuristic-score-value').textContent = heuristicScore !== undefined ? `${heuristicScore}/100` : 'N/A';

  // Risk Reason
  document.getElementById('risk-reason').textContent = reason || 'No specific risk factors detected.';

  // Technical Details
  if (features) {
    document.getElementById('tech-url-length').textContent = features.urlLength || '-';
    document.getElementById('tech-subdomains').textContent = features.numDots || '-';
    document.getElementById('tech-hyphens').textContent = features.numHyphens || '-';
    document.getElementById('tech-ip').textContent = features.hasIP ? '⚠️ Yes' : '✅ No';
    document.getElementById('tech-entropy').textContent = features.domainEntropy ? features.domainEntropy.toFixed(2) : '-';
    document.getElementById('tech-special').textContent = features.numSpecialChars || '-';

    // Colorize IP warning
    const ipElement = document.getElementById('tech-ip');
    if (features.hasIP) {
      ipElement.style.color = '#dc3545';
      ipElement.style.fontWeight = '700';
    } else {
      ipElement.style.color = '#28a745';
    }
  }
}

function showError() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('error').style.display = 'block';
}
