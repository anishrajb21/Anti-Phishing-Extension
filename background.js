// PhishLens Web Shield - Background Service Worker
// Monitors all web navigation and performs real-time phishing detection

// Store detection results
const detectionCache = new Map();
let mlModel = null;

// Known legitimate brand domains for typosquatting detection
const KNOWN_BRANDS = [
  'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
  'paypal.com', 'ebay.com', 'netflix.com', 'linkedin.com', 'twitter.com',
  'instagram.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com'
];

// Suspicious TLDs
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click', 
  '.link', '.download', '.racing', '.party', '.science', '.stream'
];

// Load ML model on startup
async function loadModel() {
  try {
    const response = await fetch(chrome.runtime.getURL('model/phishing_model.json'));
    mlModel = await response.json();
    console.log('PhishLens: ML model loaded successfully');
  } catch (error) {
    console.error('PhishLens: Error loading model:', error);
  }
}

// Extract features from URL
function extractFeatures(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const fullUrl = url;

    // Feature 1: URL Length
    const urlLength = fullUrl.length;

    // Feature 2: Number of dots (subdomains)
    const numDots = (hostname.match(/\./g) || []).length;

    // Feature 3: Number of hyphens
    const numHyphens = (hostname.match(/-/g) || []).length;

    // Feature 4: Has IP address
    const hasIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    // Feature 5: Protocol (HTTPS = 1, HTTP = 0)
    const hasHTTPS = urlObj.protocol === 'https:' ? 1 : 0;

    // Feature 6: Suspicious TLD
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld)) ? 1 : 0;

    // Feature 7: Number of special characters
    const numSpecialChars = (fullUrl.match(/[@&=_\?]/g) || []).length;

    // Feature 8: Domain entropy (measure of randomness)
    const domainEntropy = calculateEntropy(hostname);

    // Feature 9: Typosquatting detection
    const typosquattingScore = detectTyposquatting(hostname);

    // Feature 10: Number of digits in domain
    const numDigits = (hostname.match(/\d/g) || []).length;

    // Feature 11: Length of hostname
    const hostnameLength = hostname.length;

    // Feature 12: Has @ symbol (often used in phishing)
    const hasAtSymbol = fullUrl.includes('@') ? 1 : 0;

    return {
      urlLength,
      numDots,
      numHyphens,
      hasIP,
      hasHTTPS,
      hasSuspiciousTLD,
      numSpecialChars,
      domainEntropy,
      typosquattingScore,
      numDigits,
      hostnameLength,
      hasAtSymbol
    };
  } catch (error) {
    console.error('Error extracting features:', error);
    return null;
  }
}

// Calculate Shannon entropy
function calculateEntropy(str) {
  const len = str.length;
  const frequencies = {};
  
  for (let char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (let char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

// Detect typosquatting using Levenshtein distance
function detectTyposquatting(hostname) {
  let minDistance = Infinity;
  
  for (let brand of KNOWN_BRANDS) {
    const distance = levenshteinDistance(hostname, brand);
    if (distance < minDistance) {
      minDistance = distance;
    }
  }
  
  // Return normalized score (0-1, higher = more suspicious)
  return Math.min(minDistance / 10, 1);
}

// Levenshtein distance algorithm
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

// ML model prediction using trained weights
function predictWithML(features) {
  if (!mlModel) return 0.5;

  // Simple logistic regression using the trained weights
  let score = mlModel.bias;
  const featureArray = [
    features.urlLength / 100, // Normalize
    features.numDots / 5,
    features.numHyphens / 5,
    features.hasIP,
    features.hasHTTPS,
    features.hasSuspiciousTLD,
    features.numSpecialChars / 10,
    features.domainEntropy / 5,
    features.typosquattingScore,
    features.numDigits / 10,
    features.hostnameLength / 50,
    features.hasAtSymbol
  ];

  for (let i = 0; i < featureArray.length; i++) {
    score += featureArray[i] * mlModel.weights[i];
  }

  // Sigmoid function
  return 1 / (1 + Math.exp(-score));
}

// Heuristic-based detection
function heuristicDetection(url, features) {
  let riskScore = 0;

  // Rule 1: Very long URLs are suspicious
  if (features.urlLength > 75) riskScore += 15;
  else if (features.urlLength > 54) riskScore += 10;

  // Rule 2: IP address instead of domain
  if (features.hasIP) riskScore += 25;

  // Rule 3: No HTTPS
  if (!features.hasHTTPS) riskScore += 20;

  // Rule 4: Suspicious TLD
  if (features.hasSuspiciousTLD) riskScore += 20;

  // Rule 5: Too many subdomains
  if (features.numDots > 4) riskScore += 15;
  else if (features.numDots > 3) riskScore += 10;

  // Rule 6: Many hyphens (typosquatting indicator)
  if (features.numHyphens > 3) riskScore += 15;
  else if (features.numHyphens > 1) riskScore += 8;

  // Rule 7: @ symbol in URL
  if (features.hasAtSymbol) riskScore += 25;

  // Rule 8: High entropy (random-looking domain)
  if (features.domainEntropy > 4) riskScore += 10;

  // Rule 9: Typosquatting detection
  if (features.typosquattingScore < 0.3 && features.typosquattingScore > 0) {
    riskScore += 30; // Very similar to known brand
  }

  // Rule 10: Too many digits in domain
  if (features.numDigits > 4) riskScore += 10;

  return Math.min(riskScore, 100);
}

// Combined detection (ML + Heuristics)
async function analyzeURL(url) {
  const features = extractFeatures(url);
  if (!features) return { safe: true, score: 0, reason: 'Unable to analyze' };

  // Get ML prediction (0-1, higher = more likely phishing)
  const mlScore = predictWithML(features);

  // Get heuristic score (0-100)
  const heuristicScore = heuristicDetection(url, features);

  // Combine scores (weighted average)
  const combinedScore = Math.round((mlScore * 50) + (heuristicScore * 0.5));

  // Determine safety (lowered threshold for more protection)
  const safe = combinedScore < 40;
  
  let reason = '';
  if (features.hasIP) reason += 'IP address used. ';
  if (!features.hasHTTPS) reason += 'No HTTPS. ';
  if (features.hasSuspiciousTLD) reason += 'Suspicious domain extension. ';
  if (features.typosquattingScore < 0.3 && features.typosquattingScore > 0) {
    reason += 'Resembles known brand (possible typosquatting). ';
  }
  if (features.hasAtSymbol) reason += 'Contains @ symbol. ';

  return {
    safe,
    score: combinedScore,
    reason: reason || (safe ? 'No suspicious indicators detected.' : 'Multiple risk factors detected.'),
    features,
    mlScore: Math.round(mlScore * 100),
    heuristicScore
  };
}

// Check domain age using WHOIS API (optional - requires internet)
async function checkDomainAge(hostname) {
  try {
    // Using a free WHOIS API
    const response = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName=${hostname}&outputFormat=JSON`, {
      signal: AbortSignal.timeout(3000)
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.WhoisRecord && data.WhoisRecord.createdDate) {
        const createdDate = new Date(data.WhoisRecord.createdDate);
        const ageInDays = Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24));
        return ageInDays;
      }
    }
  } catch (error) {
    // Silently fail - WHOIS is optional
  }
  return null;
}

// Listen to web navigation events BEFORE they commit
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  
  // Skip chrome:// and extension pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

  console.log('PhishLens: Analyzing URL BEFORE navigation:', url);

  // Perform quick analysis
  const result = await analyzeURL(url);
  
  // Get domain age asynchronously (don't wait for it)
  try {
    const urlObj = new URL(url);
    checkDomainAge(urlObj.hostname).then(age => {
      if (age !== null) {
        const cached = detectionCache.get(details.tabId);
        if (cached && cached.url === url) {
          cached.domainAge = age;
        }
      }
    });
  } catch (error) {
    // Ignore domain age errors
  }
  
  // Store result immediately
  detectionCache.set(details.tabId, {
    url,
    ...result,
    timestamp: Date.now()
  });

  // Update badge immediately
  updateBadge(details.tabId, result.safe, result.score);

  // If unsafe, prepare to block
  if (!result.safe && result.score >= 40) {
    console.log('PhishLens: BLOCKING unsafe URL:', url, 'Score:', result.score);
    
    // Redirect to warning page
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('popup/blocked.html') + '?url=' + encodeURIComponent(url) + '&score=' + result.score + '&reason=' + encodeURIComponent(result.reason)
    });
  }
});

// Listen to web navigation events (for badge updates)
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only process main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  
  // Skip chrome:// and extension pages and our blocked page
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

  console.log('PhishLens: Page committed, ensuring analysis exists for:', url);

  // Check if we already have cached result
  let result = detectionCache.get(details.tabId);
  
  // If no result or different URL, analyze now
  if (!result || result.url !== url) {
    console.log('PhishLens: No cached result, analyzing now');
    result = await analyzeURL(url);
    
    // Get domain age asynchronously
    try {
      const urlObj = new URL(url);
      checkDomainAge(urlObj.hostname).then(age => {
        if (age !== null) {
          const cached = detectionCache.get(details.tabId);
          if (cached && cached.url === url) {
            cached.domainAge = age;
          }
        }
      });
    } catch (error) {
      // Ignore
    }
    
    detectionCache.set(details.tabId, {
      url,
      ...result,
      timestamp: Date.now()
    });
  }

  // Update badge
  updateBadge(details.tabId, result.safe, result.score);
  
  // Send message to content script to show notification
  try {
    await chrome.tabs.sendMessage(details.tabId, {
      action: 'showWarning',
      safe: result.safe,
      score: result.score,
      reason: result.reason
    });
  } catch (error) {
    // Content script might not be ready yet
  }
});

// Update extension badge
function updateBadge(tabId, safe, score) {
  const color = safe ? '#00AA00' : '#FF0000';
  const text = safe ? '✓' : '!';
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getAnalysis') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const result = detectionCache.get(tabs[0].id);
        sendResponse(result || null);
      } else {
        sendResponse(null);
      }
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'analyzeURL') {
    // Analyze the requested URL immediately
    (async () => {
      try {
        console.log('PhishLens: Manual analysis request for:', request.url);
        const result = await analyzeURL(request.url);
        
        // Get domain age asynchronously
        try {
          const urlObj = new URL(request.url);
          const age = await checkDomainAge(urlObj.hostname);
          if (age !== null) {
            result.domainAge = age;
          }
        } catch (error) {
          result.domainAge = null;
        }
        
        // Store in cache
        if (request.tabId) {
          detectionCache.set(request.tabId, {
            url: request.url,
            ...result,
            timestamp: Date.now()
          });
          
          // Update badge
          updateBadge(request.tabId, result.safe, result.score);
        }
        
        sendResponse({
          url: request.url,
          ...result,
          timestamp: Date.now()
        });
      } catch (error) {
        console.error('PhishLens: Error during manual analysis:', error);
        sendResponse(null);
      }
    })();
    return true; // Keep channel open for async response
  }
});

// Clean up old cache entries
setInterval(() => {
  const now = Date.now();
  for (let [tabId, data] of detectionCache.entries()) {
    if (now - data.timestamp > 300000) { // 5 minutes
      detectionCache.delete(tabId);
    }
  }
}, 60000);

// Initialize
loadModel();
console.log('PhishLens Web Shield: Background service worker initialized');
