import test from 'node:test';
import assert from 'node:assert/strict';

import { parseDomain } from '../../src/utils/psl.js';
import { 
  normalizeHomoglyphs, 
  normalizeLeetspeak, 
  levenshteinDistance, 
  detectImpersonation 
} from '../../src/utils/homoglyphs.js';
import { safeParseURL, MalformedURLError, UnsupportedSchemeError } from '../../src/engine/urlParser.js';
import { extractFeatures, calculateEntropy } from '../../src/engine/featureExtractor.js';
import { evaluateHeuristics } from '../../src/engine/heuristicEngine.js';
import { MLEngine } from '../../src/engine/mlEngine.js';
import { ThreatIntelManager, LocalThreatIntelProvider } from '../../src/engine/threatIntelligence.js';
import { RiskScorer } from '../../src/engine/riskScorer.js';
import { SessionManager } from '../../src/engine/sessionManager.js';

test('PSL Domain Parser correctly decomposes standard and multi-part domains', () => {
  const d1 = parseDomain('login.paypal.com');
  assert.equal(d1.domainLabel, 'paypal');
  assert.equal(d1.registrableDomain, 'paypal.com');
  assert.equal(d1.subdomain, 'login');
  assert.equal(d1.publicSuffix, 'com');
  assert.equal(d1.isIP, false);

  const d2 = parseDomain('attacker.co.uk');
  assert.equal(d2.domainLabel, 'attacker');
  assert.equal(d2.registrableDomain, 'attacker.co.uk');
  assert.equal(d2.publicSuffix, 'co.uk');

  const d3 = parseDomain('paypal.com.evil.co.uk');
  assert.equal(d3.domainLabel, 'evil');
  assert.equal(d3.registrableDomain, 'evil.co.uk');
  assert.equal(d3.subdomain, 'paypal.com');

  const d4 = parseDomain('192.168.1.100');
  assert.equal(d4.isIP, true);
  assert.equal(d4.registrableDomain, '192.168.1.100');

  const d5 = parseDomain('[::1]');
  assert.equal(d5.isIP, true);
});

test('Homoglyph and Impersonation Detector identifies attacks', () => {
  // Cyrillic 'а' replacing Latin 'a'
  const cyrillicA = 'р\u0430ypal';
  assert.equal(normalizeHomoglyphs(cyrillicA), 'paypal');

  // Exact brand should not be flagged as impersonation
  const legit = detectImpersonation('paypal', 'paypal.com');
  assert.equal(legit.score, 0.0);
  assert.equal(legit.technique, 'legitimate_brand');

  // Leetspeak lookalike: paypa1
  const leet = detectImpersonation('paypa1', 'paypa1.com');
  assert.ok(leet.score >= 0.9);
  assert.equal(leet.impersonatedBrand, 'paypal');

  // Combosquatting: paypal-security
  const combo = detectImpersonation('paypal-security', 'paypal-security.com');
  assert.ok(combo.score >= 0.8);
  assert.equal(combo.impersonatedBrand, 'paypal');

  // Subdomain deception: paypal.com.attacker.com
  const subSpoof = detectImpersonation('attacker', 'paypal.com.attacker.com');
  assert.ok(subSpoof.score >= 0.8);
  assert.equal(subSpoof.impersonatedBrand, 'paypal');

  // Unrelated benign domain
  const unrelated = detectImpersonation('wikipedia', 'wikipedia.org');
  assert.equal(unrelated.score, 0.0);
});

test('URL Parser enforces supported schemes and rejects malformed URLs', () => {
  assert.throws(() => safeParseURL(''), MalformedURLError);
  assert.throws(() => safeParseURL('not a url'), MalformedURLError);
  assert.throws(() => safeParseURL('javascript:alert(1)'), UnsupportedSchemeError);
  assert.throws(() => safeParseURL('chrome://extensions'), UnsupportedSchemeError);
  assert.throws(() => safeParseURL('file:///etc/passwd'), UnsupportedSchemeError);

  const parsed = safeParseURL('https://user:pass@evil.com:8443/login?q=1#hash');
  assert.equal(parsed.valid, true);
  assert.equal(parsed.protocol, 'https:');
  assert.equal(parsed.hostname, 'evil.com');
  assert.equal(parsed.hasUserInfo, true);
  assert.equal(parsed.isStandardPort, false);
  assert.equal(parsed.port, '8443');
});

test('Feature Extractor produces bounded normalized vector and metadata', () => {
  const url = 'https://login.paypal-security.xyz:8080/auth?ref=portal';
  const features = extractFeatures(url);

  assert.equal(features.normalized.length, 12);
  assert.equal(features.raw.hasHTTPS, 1);
  assert.equal(features.raw.hasSuspiciousTLD, 1);
  assert.ok(features.raw.domainEntropy > 0);
  assert.ok(features.raw.typosquattingScore > 0);

  // Normalization should be non-negative and bounded
  for (const val of features.normalized) {
    assert.ok(val >= 0 && val <= 5.0, `Value ${val} out of bounds`);
  }
});

test('Heuristic Engine produces structured reasons and calibrated scores', () => {
  // Safe URL
  const safeFeatures = extractFeatures('https://www.google.com/search?q=cybersecurity');
  const safeHeuristics = evaluateHeuristics(safeFeatures);
  assert.ok(safeHeuristics.score < 20);

  // Severe Phishing URL: IP address + authority trick + non-standard port + no HTTPS
  const evilUrl = 'http://admin:pass@192.168.1.1:8888/login';
  const evilFeatures = extractFeatures(evilUrl);
  const evilHeuristics = evaluateHeuristics(evilFeatures);

  assert.ok(evilHeuristics.score >= 70);
  const reasonIds = evilHeuristics.reasons.map(r => r.id);
  assert.ok(reasonIds.includes('AUTHORITY_OBFUSCATION'));
  assert.ok(reasonIds.includes('RAW_IP_HOST'));
  assert.ok(reasonIds.includes('NON_STANDARD_PORT'));
  assert.ok(reasonIds.includes('INSECURE_HTTP'));
});

test('ML Engine handles model loading, inference, and uninitialized state safely', () => {
  const engine = new MLEngine();
  // Uninitialized should return status MODEL_UNAVAILABLE, not crash or fake safe
  const uninitResult = engine.predict([1, 2, 3]);
  assert.equal(uninitResult.available, false);
  assert.equal(uninitResult.status, 'MODEL_UNAVAILABLE');

  // Load a model
  engine.loadModel({
    modelType: 'logistic_regression',
    version: '1.0.0',
    weights: [0.5, -0.5, 2.0],
    bias: -1.0,
    threshold: 0.5
  });

  const pred1 = engine.predict([1, 1, 1]); // z = -1.0 + 0.5 - 0.5 + 2.0 = 1.0 -> sigmoid(1) = 0.731
  assert.equal(pred1.available, true);
  assert.ok(pred1.probability > 0.7);
  assert.equal(pred1.isPhishing, true);

  // Feature length mismatch
  const mismatch = engine.predict([1, 2]);
  assert.equal(mismatch.status, 'FEATURE_MISMATCH');
});

test('Threat Intelligence Manager supports caching, provider queries, and graceful fallbacks', async () => {
  const provider = new LocalThreatIntelProvider({
    maliciousDomains: ['phish-test.xyz'],
    knownSafeDomains: ['trusted-bank.com']
  });
  const manager = new ThreatIntelManager([provider]);

  const badResult = await manager.check('phish-test.xyz');
  assert.equal(badResult.verdict, 'KNOWN_MALICIOUS');

  // Check that result is cached
  const badCached = await manager.check('phish-test.xyz');
  assert.equal(badCached.cached, true);

  const goodResult = await manager.check('trusted-bank.com');
  assert.equal(goodResult.verdict, 'SAFE');

  const unknownResult = await manager.check('completely-unseen-domain.com');
  assert.equal(unknownResult.verdict, 'UNKNOWN');
});

test('Risk Scorer categorizes risk without claiming definitive safety', async () => {
  const scorer = new RiskScorer();

  // Malformed URL should yield ERROR and safe=false!
  const errVerdict = await scorer.analyze('javascript:void(0)');
  assert.equal(errVerdict.category, 'ERROR');
  assert.equal(errVerdict.safe, false);

  // Legitimate site
  const legitVerdict = await scorer.analyze('https://www.wikipedia.org/wiki/Phishing');
  assert.equal(legitVerdict.category, 'LOW_RISK');
  assert.equal(legitVerdict.safe, true);
  assert.ok(legitVerdict.summary.includes('does not guarantee absolute legitimacy') || legitVerdict.summary.includes('acceptable parameters'));

  // Spoofed site
  const spoofVerdict = await scorer.analyze('https://paypa1-security.xyz/login');
  assert.ok(spoofVerdict.category === 'SUSPICIOUS' || spoofVerdict.category === 'HIGH_RISK');
  assert.equal(spoofVerdict.safe, false);
});

test('Session Manager maintains cache and prevents redirect loops via bypass allowlist', () => {
  const sm = new SessionManager({ cacheTtlMs: 1000, bypassTtlMs: 2000 });
  const tabId = 42;
  const url = 'https://unsafe-test.com/login';

  assert.equal(sm.isBypassed(tabId, url), false);

  // User authorizes bypass
  sm.grantBypass(tabId, url);
  assert.equal(sm.isBypassed(tabId, url), true);

  // Bypass should be specific to tab and URL
  assert.equal(sm.isBypassed(99, url), false);
  assert.equal(sm.isBypassed(tabId, 'https://another-site.com'), false);

  // Cache test
  sm.setAnalysis(tabId, url, { score: 85 });
  assert.deepEqual(sm.getAnalysis(tabId, url), { score: 85 });

  // Tab closed
  sm.clearTab(tabId);
  assert.equal(sm.getAnalysis(tabId, url), null);
  assert.equal(sm.isBypassed(tabId, url), false);
});
