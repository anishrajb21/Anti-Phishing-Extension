/**
 * Session State & Navigation Bypass Manager
 * Handles tab-specific analysis caching and safe user bypass authorization.
 */

export class SessionManager {
  /**
   * @param {Object} options
   * @param {number} [options.cacheTtlMs] - Default 5 minutes
   * @param {number} [options.bypassTtlMs] - Default 10 minutes
   * @param {number} [options.maxCacheEntries] - Default 200
   */
  constructor(options = {}) {
    this.cacheTtl = options.cacheTtlMs ?? 5 * 60 * 1000;
    this.bypassTtl = options.bypassTtlMs ?? 10 * 60 * 1000;
    this.maxCacheEntries = options.maxCacheEntries ?? 200;

    // In-memory cache structures (mirrored to chrome.storage.session when available)
    this.analysisCache = new Map(); // key: `${tabId}:${url}` -> { data, timestamp }
    this.bypassList = new Map();     // key: `${tabId}:${url}` -> { timestamp, expiresAt }
  }

  /**
   * Generates a stable composite key for a tab and URL.
   * @param {number} tabId
   * @param {string} url
   * @returns {string}
   */
  static getKey(tabId, url) {
    if (!url) return `${tabId}:`;
    try {
      const u = new URL(url);
      // Strip fragment/hash for caching key
      return `${tabId}:${u.origin}${u.pathname}${u.search}`;
    } catch {
      return `${tabId}:${url}`;
    }
  }

  /**
   * Registers a user bypass grant for a specific tab and URL.
   * Prevents infinite redirect loops when a user explicitly chooses "Proceed Anyway".
   * 
   * @param {number} tabId
   * @param {string} url
   */
  grantBypass(tabId, url) {
    const key = SessionManager.getKey(tabId, url);
    const now = Date.now();
    this.bypassList.set(key, {
      timestamp: now,
      expiresAt: now + this.bypassTtl
    });
  }

  /**
   * Checks if a tab has an active bypass authorization for the target URL.
   * 
   * @param {number} tabId
   * @param {string} url
   * @returns {boolean}
   */
  isBypassed(tabId, url) {
    const key = SessionManager.getKey(tabId, url);
    const entry = this.bypassList.get(key);
    if (!entry) return false;

    if (Date.now() > entry.expiresAt) {
      this.bypassList.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Revokes bypass grant for a tab and URL.
   * @param {number} tabId
   * @param {string} url
   */
  revokeBypass(tabId, url) {
    const key = SessionManager.getKey(tabId, url);
    this.bypassList.delete(key);
  }

  /**
   * Stores analysis result in session cache.
   * @param {number} tabId
   * @param {string} url
   * @param {any} result
   */
  setAnalysis(tabId, url, result) {
    const key = SessionManager.getKey(tabId, url);
    if (this.analysisCache.size >= this.maxCacheEntries) {
      const oldestKey = this.analysisCache.keys().next().value;
      this.analysisCache.delete(oldestKey);
    }
    this.analysisCache.set(key, {
      result,
      timestamp: Date.now()
    });
  }

  /**
   * Retrieves analysis result from session cache if not expired.
   * @param {number} tabId
   * @param {string} url
   * @returns {any | null}
   */
  getAnalysis(tabId, url) {
    const key = SessionManager.getKey(tabId, url);
    const entry = this.analysisCache.get(key);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > this.cacheTtl) {
      this.analysisCache.delete(key);
      return null;
    }
    return entry.result;
  }

  /**
   * Cleans expired cache entries.
   */
  prune() {
    const now = Date.now();
    for (const [key, entry] of this.analysisCache.entries()) {
      if (now - entry.timestamp > this.cacheTtl) {
        this.analysisCache.delete(key);
      }
    }
    for (const [key, entry] of this.bypassList.entries()) {
      if (now > entry.expiresAt) {
        this.bypassList.delete(key);
      }
    }
  }

  /**
   * Clears all state for a tab when it closes.
   * @param {number} tabId
   */
  clearTab(tabId) {
    const prefix = `${tabId}:`;
    for (const key of this.analysisCache.keys()) {
      if (key.startsWith(prefix)) this.analysisCache.delete(key);
    }
    for (const key of this.bypassList.keys()) {
      if (key.startsWith(prefix)) this.bypassList.delete(key);
    }
  }
}
