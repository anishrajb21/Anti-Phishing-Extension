import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RiskScorer } from '../../src/engine/riskScorer.js';
import { MLEngine } from '../../src/engine/mlEngine.js';
import { 
  ThreatIntelManager, 
  BaseThreatIntelProvider, 
  LocalThreatIntelProvider 
} from '../../src/engine/threatIntelligence.js';
import { SessionManager } from '../../src/engine/sessionManager.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODEL_FILE_PATH = path.resolve(__dirname, '../../model/phishing_model.json');

// Mock Failing Threat Intelligence Provider
class FlakyThreatProvider extends BaseThreatIntelProvider {
  constructor() {
    super('FlakyProvider');
  }
  async checkDomain(hostname) {
    throw new Error('Network socket disconnected or rate-limited');
  }
}

// Mock Slow Provider
class HangingThreatProvider extends BaseThreatIntelProvider {
  constructor() {
    super('HangingProvider');
  }
  async checkDomain(hostname) {
    await new Promise(resolve => setTimeout(resolve, 5000));
    return { verdict: 'SAFE', provider: this.name, confidence: 1, timestamp: Date.now() };
  }
}

test('Integration: End-to-end detection pipeline with real exported model', async () => {
  const modelConfig = JSON.parse(fs.readFileSync(MODEL_FILE_PATH, 'utf-8'));
  const mlEngine = new MLEngine(modelConfig);
  const threatIntelManager = new ThreatIntelManager([new LocalThreatIntelProvider()]);
  const scorer = new RiskScorer({ mlEngine, threatIntelManager });

  // 1. Legitimate website test
  const legitRes = await scorer.analyze('https://www.google.com/search?q=cybersecurity');
  assert.equal(legitRes.category, 'LOW_RISK');
  assert.equal(legitRes.safe, true);
  assert.ok(legitRes.score < 35);
  assert.equal(legitRes.details.ml.available, true);
  assert.ok(legitRes.details.ml.probability < 0.40);

  // 2. Phishing URL test (combining leetspeak brand impersonation on suspicious TLD)
  const phishRes = await scorer.analyze('https://paypa1-security-verification.xyz/login');
  assert.ok(phishRes.category === 'SUSPICIOUS' || phishRes.category === 'HIGH_RISK');
  assert.equal(phishRes.safe, false);
  assert.ok(phishRes.score >= 35);
  assert.ok(phishRes.reasons.length > 0);

  // 3. Known Threat Intel malicious domain
  const threatRes = await scorer.analyze('https://paypal-security-update-fake.xyz/confirm');
  assert.equal(threatRes.category, 'HIGH_RISK');
  assert.equal(threatRes.safe, false);
  assert.ok(threatRes.score >= 90);
  assert.equal(threatRes.details.threatIntel.verdict, 'KNOWN_MALICIOUS');
});

test('Integration: Threat Intelligence provider failures and timeouts degrade gracefully', async () => {
  const modelConfig = JSON.parse(fs.readFileSync(MODEL_FILE_PATH, 'utf-8'));
  const mlEngine = new MLEngine(modelConfig);

  // Both flaky and hanging providers
  const resilientManager = new ThreatIntelManager([
    new FlakyThreatProvider(),
    new HangingThreatProvider()
  ]);

  const scorer = new RiskScorer({ mlEngine, threatIntelManager: resilientManager });

  // Should NOT throw an uncaught exception, but gracefully fall back to Heuristics + ML
  const start = Date.now();
  const verdict = await scorer.analyze('https://example.com/test');
  const elapsed = Date.now() - start;

  assert.ok(elapsed < 2500, 'Must time out slow threat provider within configured timeout');
  assert.ok(verdict.category === 'LOW_RISK' || verdict.category === 'SUSPICIOUS');
  assert.equal(verdict.details.threatIntel.verdict, 'UNKNOWN');
});

test('Integration: Session Manager caching, expiration, and navigation bypass prevention', async () => {
  const sm = new SessionManager({ cacheTtlMs: 200, bypassTtlMs: 400 });
  const tabId = 101;
  const maliciousUrl = 'https://attacker-login.xyz/auth';

  // 1. Initial State: not bypassed
  assert.equal(sm.isBypassed(tabId, maliciousUrl), false);

  // 2. User confirms "Proceed Anyway": grant bypass
  sm.grantBypass(tabId, maliciousUrl);
  assert.equal(sm.isBypassed(tabId, maliciousUrl), true);

  // 3. Different tab or URL must NOT be bypassed
  assert.equal(sm.isBypassed(999, maliciousUrl), false);
  assert.equal(sm.isBypassed(tabId, 'https://another-site.com'), false);

  // 4. Cache storing and TTL expiration
  sm.setAnalysis(tabId, maliciousUrl, { score: 92, category: 'HIGH_RISK' });
  assert.equal(sm.getAnalysis(tabId, maliciousUrl).score, 92);

  // Wait for cache TTL (200ms)
  await new Promise(resolve => setTimeout(resolve, 250));
  assert.equal(sm.getAnalysis(tabId, maliciousUrl), null);

  // Bypass should still be active (400ms TTL)
  assert.equal(sm.isBypassed(tabId, maliciousUrl), true);

  // Wait for bypass TTL (400ms)
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(sm.isBypassed(tabId, maliciousUrl), false);
});

test('Integration: Verdict contract matches all UI data binding requirements', async () => {
  const modelConfig = JSON.parse(fs.readFileSync(MODEL_FILE_PATH, 'utf-8'));
  const scorer = new RiskScorer({ mlEngine: new MLEngine(modelConfig) });

  const verdict = await scorer.analyze('https://login.microsoft.com.account-update.link/auth');

  // Verify all contract keys required by popup.js and blocked.js
  assert.equal(typeof verdict.safe, 'boolean');
  assert.ok(['LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'ERROR'].includes(verdict.category));
  assert.equal(typeof verdict.score, 'number');
  assert.equal(typeof verdict.summary, 'string');
  assert.ok(Array.isArray(verdict.reasons));
  assert.equal(typeof verdict.url, 'string');
  assert.equal(typeof verdict.hostname, 'string');
  assert.equal(typeof verdict.timestamp, 'number');

  // Structure of details
  assert.ok(verdict.details);
  assert.ok(verdict.details.ml);
  assert.ok(verdict.details.heuristic);
  assert.ok(verdict.details.threatIntel);
  assert.ok(verdict.details.features);
  assert.ok(verdict.details.domain);

  // Reasons item schema
  for (const r of verdict.reasons) {
    assert.ok(r.id);
    assert.ok(r.severity);
    assert.ok(r.title);
    assert.ok(r.description);
  }
});
