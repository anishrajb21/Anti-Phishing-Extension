/**
 * Threat Intelligence Layer
 * Privacy-preserving, cached, and failure-tolerant threat intelligence interface.
 */

/**
 * @typedef {'KNOWN_MALICIOUS' | 'SUSPICIOUS' | 'SAFE' | 'UNKNOWN'} ThreatVerdict
 */

/**
 * @typedef {Object} ThreatIntelResult
 * @property {ThreatVerdict} verdict
 * @property {string} provider
 * @property {number} confidence - 0.0 to 1.0
 * @property {string} [threatType] - e.g. "phishing", "malware"
 * @property {number} timestamp
 * @property {boolean} cached
 * @property {string | null} details
 */

export class ThreatIntelCache {
  /**
   * @param {number} defaultTtlMs - Cache time-to-live (default 10 minutes)
   * @param {number} maxEntries - Bounded capacity
   */
  constructor(defaultTtlMs = 10 * 60 * 1000, maxEntries = 500) {
    this.ttl = defaultTtlMs;
    this.maxEntries = maxEntries;
    this.cache = new Map();
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }
    return { ...entry.data, cached: true };
  }

  set(key, data) {
    if (this.cache.size >= this.maxEntries) {
      // Evict oldest entry (LRU-like eviction)
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  clear() {
    this.cache.clear();
  }
}

/**
 * Threat Intelligence Provider Interface (Base Class)
 */
export class BaseThreatIntelProvider {
  constructor(name) {
    this.name = name;
  }

  /**
   * Checks domain reputation. NEVER sends full URL or query strings.
   * @param {string} hostname
   * @returns {Promise<ThreatIntelResult>}
   */
  async checkDomain(hostname) {
    throw new Error('checkDomain must be implemented by provider');
  }
}

/**
 * Local Curated Threat Feed & Safelist Provider
 * Performs zero external network requests by default.
 */
export class LocalThreatIntelProvider extends BaseThreatIntelProvider {
  constructor(options = {}) {
    super('LocalFeed');
    this.maliciousDomains = new Set(options.maliciousDomains || [
      'evil-phishing-example.com',
      'paypal-security-update-fake.xyz',
      'google-account-verify-login.top',
      'microsoft-verify-token.link'
    ]);
    this.knownSafeDomains = new Set(options.knownSafeDomains || [
      'google.com', 'apple.com', 'microsoft.com', 'github.com',
      'wikipedia.org', 'amazon.com', 'mozilla.org', 'cloudflare.com'
    ]);
  }

  async checkDomain(hostname) {
    const host = hostname.toLowerCase().trim();

    if (this.maliciousDomains.has(host)) {
      return {
        verdict: 'KNOWN_MALICIOUS',
        provider: this.name,
        confidence: 0.99,
        threatType: 'phishing',
        timestamp: Date.now(),
        cached: false,
        details: 'Domain matches high-confidence local threat intelligence signature.'
      };
    }

    if (this.knownSafeDomains.has(host)) {
      return {
        verdict: 'SAFE',
        provider: this.name,
        confidence: 0.90,
        threatType: null,
        timestamp: Date.now(),
        cached: false,
        details: 'Domain is in local verified legitimate brand repository.'
      };
    }

    // Absence from threat feed is NEVER proof of legitimacy!
    return {
      verdict: 'UNKNOWN',
      provider: this.name,
      confidence: 0.0,
      threatType: null,
      timestamp: Date.now(),
      cached: false,
      details: 'No local reputation entries found for this domain.'
    };
  }
}

/**
 * Threat Intelligence Coordinator
 */
export class ThreatIntelManager {
  /**
   * @param {BaseThreatIntelProvider[]} providers
   * @param {ThreatIntelCache} [cache]
   */
  constructor(providers = [new LocalThreatIntelProvider()], cache = new ThreatIntelCache()) {
    this.providers = providers;
    this.cache = cache;
  }

  /**
   * Queries threat intelligence for a hostname with caching and timeouts.
   * @param {string} hostname
   * @param {number} [timeoutMs]
   * @returns {Promise<ThreatIntelResult>}
   */
  async check(hostname, timeoutMs = 2000) {
    if (!hostname) {
      return {
        verdict: 'UNKNOWN',
        provider: 'none',
        confidence: 0,
        timestamp: Date.now(),
        cached: false,
        details: 'Empty hostname'
      };
    }

    const cached = this.cache.get(hostname);
    if (cached) return cached;

    for (const provider of this.providers) {
      try {
        const checkPromise = provider.checkDomain(hostname);
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Provider timeout')), timeoutMs)
        );

        const result = await Promise.race([checkPromise, timeoutPromise]);
        if (result && result.verdict !== 'UNKNOWN') {
          this.cache.set(hostname, result);
          return result;
        }
      } catch (err) {
        // Provider failed or timed out - degrade gracefully
        console.warn(`[ThreatIntel] Provider ${provider.name} failed:`, err.message);
      }
    }

    const neutralResult = {
      verdict: 'UNKNOWN',
      provider: 'none',
      confidence: 0.0,
      threatType: null,
      timestamp: Date.now(),
      cached: false,
      details: 'No definitive threat feed record found (absence is not proof of safety).'
    };

    this.cache.set(hostname, neutralResult);
    return neutralResult;
  }
}
