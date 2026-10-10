/**
 * Feature Extraction Engine for Heuristics and Machine Learning
 */

import { safeParseURL } from './urlParser.js';
import { detectImpersonation } from '../utils/homoglyphs.js';

export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
  'link', 'download', 'racing', 'party', 'science', 'stream',
  'club', 'loan', 'cam', 'country', 'buzz', 'rest', 'fit', 'guru'
]);

/**
 * Calculates Shannon Entropy of a string.
 * @param {string} str
 * @returns {number}
 */
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const frequencies = {};

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Normalizes a scalar feature with an optional upper bound.
 * @param {number} value
 * @param {number} divisor
 * @param {number} maxCap
 * @returns {number}
 */
function normalizeScalar(value, divisor, maxCap = 5.0) {
  const norm = value / divisor;
  return Math.min(norm, maxCap);
}

/**
 * Extracts raw and normalized features from a URL.
 * 
 * @param {string | ReturnType<typeof safeParseURL>} parsedOrUrl
 * @returns {{
 *   raw: {
 *     urlLength: number,
 *     numDots: number,
 *     numHyphens: number,
 *     hasIP: number,
 *     hasHTTPS: number,
 *     hasSuspiciousTLD: number,
 *     numSpecialChars: number,
 *     domainEntropy: number,
 *     typosquattingScore: number,
 *     numDigits: number,
 *     hostnameLength: number,
 *     hasAtSymbol: number
 *   },
 *   normalized: number[],
 *   featureNames: string[],
 *   metadata: {
 *     parsed: ReturnType<typeof safeParseURL>,
 *     impersonation: ReturnType<typeof detectImpersonation>
 *   }
 * }}
 */
export function extractFeatures(parsedOrUrl) {
  const parsed = typeof parsedOrUrl === 'string' ? safeParseURL(parsedOrUrl) : parsedOrUrl;
  const fullUrl = parsed.url;
  const hostname = parsed.hostname;
  const domain = parsed.domain;

  // 1. URL Length
  const urlLength = fullUrl.length;

  // 2. Number of dots in hostname
  const numDots = (hostname.match(/\./g) || []).length;

  // 3. Number of hyphens in hostname
  const numHyphens = (hostname.match(/-/g) || []).length;

  // 4. IP address host
  const hasIP = parsed.isIP ? 1 : 0;

  // 5. HTTPS protocol
  const hasHTTPS = parsed.protocol === 'https:' ? 1 : 0;

  // 6. Suspicious TLD check
  const suffix = domain.publicSuffix.toLowerCase();
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.has(suffix) ? 1 : 0;

  // 7. Special characters in full URL
  const numSpecialChars = (fullUrl.match(/[@&=_\?]/g) || []).length;

  // 8. Domain entropy
  const domainEntropy = calculateEntropy(hostname);

  // 9. Typosquatting / Brand Impersonation Score [0.0 - 1.0]
  const impersonation = detectImpersonation(domain.domainLabel, hostname);
  const typosquattingScore = impersonation.score;

  // 10. Number of digits in hostname
  const numDigits = (hostname.match(/\d/g) || []).length;

  // 11. Hostname length
  const hostnameLength = hostname.length;

  // 12. Has @ symbol trick in authority (userinfo)
  const hasAtSymbol = parsed.hasUserInfo ? 1 : 0;

  const raw = {
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

  const featureNames = [
    'urlLength_normalized',
    'numDots_normalized',
    'numHyphens_normalized',
    'hasIP',
    'hasHTTPS',
    'hasSuspiciousTLD',
    'numSpecialChars_normalized',
    'domainEntropy_normalized',
    'typosquattingScore',
    'numDigits_normalized',
    'hostnameLength_normalized',
    'hasAtSymbol'
  ];

  // Bounded normalization
  const normalized = [
    normalizeScalar(urlLength, 100),
    normalizeScalar(numDots, 5),
    normalizeScalar(numHyphens, 5),
    hasIP,
    hasHTTPS,
    hasSuspiciousTLD,
    normalizeScalar(numSpecialChars, 10),
    normalizeScalar(domainEntropy, 5),
    typosquattingScore,
    normalizeScalar(numDigits, 10),
    normalizeScalar(hostnameLength, 50),
    hasAtSymbol
  ];

  return {
    raw,
    normalized,
    featureNames,
    metadata: {
      parsed,
      impersonation
    }
  };
}
