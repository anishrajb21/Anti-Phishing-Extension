/**
 * Safe WHATWG URL Parser with Security Pre-validation
 */

import { parseDomain } from '../utils/psl.js';

export class MalformedURLError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MalformedURLError';
  }
}

export class UnsupportedSchemeError extends Error {
  constructor(scheme) {
    super(`Unsupported URL scheme: ${scheme}. PhishLens only analyzes HTTP and HTTPS.`);
    this.name = 'UnsupportedSchemeError';
    this.scheme = scheme;
  }
}

/**
 * Validates and safely extracts structured URL components.
 * 
 * @param {string} rawUrl - Input URL string
 * @returns {{
 *   valid: boolean,
 *   url: string,
 *   protocol: 'http:' | 'https:',
 *   hostname: string,
 *   port: string,
 *   pathname: string,
 *   search: string,
 *   hash: string,
 *   hasUserInfo: boolean,
 *   userInfo: string,
 *   domain: ReturnType<typeof parseDomain>,
 *   isIP: boolean,
 *   isStandardPort: boolean,
 *   isIDN: boolean,
 *   error?: string
 * }}
 */
export function safeParseURL(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new MalformedURLError('URL input is empty or not a string.');
  }

  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    throw new MalformedURLError('URL string is empty.');
  }

  let urlObj;
  try {
    urlObj = new URL(trimmed);
  } catch (err) {
    throw new MalformedURLError(`Invalid URL format: ${err.message}`);
  }

  // Enforce protocol restriction
  if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
    throw new UnsupportedSchemeError(urlObj.protocol);
  }

  const hostname = urlObj.hostname.toLowerCase();
  if (!hostname || hostname.length === 0) {
    throw new MalformedURLError('URL has an empty hostname.');
  }

  // Decompose domain via PSL
  const domainInfo = parseDomain(hostname);

  // Authority trick detection:
  // e.g., https://legit.com:secret@evil.com/
  const hasUserInfo = Boolean(urlObj.username || urlObj.password);
  const userInfo = hasUserInfo ? `${urlObj.username}:${urlObj.password}` : '';

  // Port checks
  const port = urlObj.port;
  const isStandardPort = !port || 
    (urlObj.protocol === 'http:' && port === '80') || 
    (urlObj.protocol === 'https:' && port === '443');

  // IDN Punycode check
  const isIDN = hostname.includes('xn--') || /[^\u0000-\u007F]/.test(hostname);

  return {
    valid: true,
    url: urlObj.href,
    protocol: urlObj.protocol,
    hostname,
    port: port || (urlObj.protocol === 'https:' ? '443' : '80'),
    pathname: urlObj.pathname,
    search: urlObj.search,
    hash: urlObj.hash,
    hasUserInfo,
    userInfo,
    domain: domainInfo,
    isIP: domainInfo.isIP,
    isStandardPort,
    isIDN
  };
}
