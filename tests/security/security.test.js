import test from 'node:test';
import assert from 'node:assert/strict';

import { safeParseURL, MalformedURLError, UnsupportedSchemeError } from '../../src/engine/urlParser.js';
import { extractFeatures } from '../../src/engine/featureExtractor.js';
import { evaluateHeuristics } from '../../src/engine/heuristicEngine.js';
import { RiskScorer } from '../../src/engine/riskScorer.js';
import { detectImpersonation } from '../../src/utils/homoglyphs.js';

test('Security: Obfuscation with User-Info (@) authority is flagged as Critical', () => {
  // Attacker trick: Browser ignores 'google.com' and connects to 'attacker.com'
  const spoofUrl = 'https://google.com:account-security@attacker.com/login';
  const parsed = safeParseURL(spoofUrl);
  assert.equal(parsed.hasUserInfo, true);
  assert.equal(parsed.hostname, 'attacker.com');

  const features = extractFeatures(parsed);
  assert.equal(features.raw.hasAtSymbol, 1);

  const heuristics = evaluateHeuristics(features);
  const authReason = heuristics.reasons.find(r => r.id === 'AUTHORITY_OBFUSCATION');
  assert.ok(authReason, 'Must generate AUTHORITY_OBFUSCATION risk reason');
  assert.equal(authReason.severity, 'CRITICAL');
});

test('Security: Query parameter containing email with @ does NOT trigger false positive authority flag', () => {
  // Legitimate redirect with email parameter
  const emailParamUrl = 'https://accounts.google.com/signin?email=test.user@company.com';
  const parsed = safeParseURL(emailParamUrl);
  assert.equal(parsed.hasUserInfo, false);

  const features = extractFeatures(parsed);
  assert.equal(features.raw.hasAtSymbol, 0);

  const heuristics = evaluateHeuristics(features);
  const authReason = heuristics.reasons.find(r => r.id === 'AUTHORITY_OBFUSCATION');
  assert.equal(authReason, undefined, 'Must not falsely accuse query parameter email of being an authority obfuscation trick');
});

test('Security: Punycode and IDN Homoglyph Spoofing is detected', () => {
  // xn--pple-43d.com is apple.com with Cyrillic 'а'
  const idnUrl = 'https://xn--pple-43d.com/login';
  const parsed = safeParseURL(idnUrl);
  assert.equal(parsed.isIDN, true);

  const features = extractFeatures(parsed);
  assert.ok(features.metadata.parsed.isIDN);

  const heuristics = evaluateHeuristics(features);
  const idnReason = heuristics.reasons.find(r => r.id === 'IDN_PUNYCODE');
  assert.ok(idnReason, 'Must detect IDN Punycode hostname');
});

test('Security: Subdomain Brand Mimicry is caught on attacker registrable domain', () => {
  const spoofUrl = 'https://chase.com.verify-identity.untrusted-host.net/portal';
  const parsed = safeParseURL(spoofUrl);
  assert.equal(parsed.domain.registrableDomain, 'untrusted-host.net');

  const imp = detectImpersonation(parsed.domain.domainLabel, parsed.hostname);
  assert.ok(imp.score >= 0.8, 'Must detect brand chase in subdomain of untrusted host');
  assert.equal(imp.impersonatedBrand, 'chase');
  assert.equal(imp.technique, 'subdomain_deception');
});

test('Security: Non-standard ports are penalized', () => {
  const unusualPortUrl = 'http://bank-portal.com:8443/auth';
  const parsed = safeParseURL(unusualPortUrl);
  assert.equal(parsed.isStandardPort, false);
  assert.equal(parsed.port, '8443');

  const features = extractFeatures(parsed);
  const heuristics = evaluateHeuristics(features);
  const portReason = heuristics.reasons.find(r => r.id === 'NON_STANDARD_PORT');
  assert.ok(portReason, 'Must generate NON_STANDARD_PORT warning');
});

test('Security: Injection strings in URLs do not cause exceptions and are safely parsed', async () => {
  const xssUrl = 'https://example.com/<script>alert("xss")</script>?q="><img src=x onerror=alert(1)>';
  const scorer = new RiskScorer();
  const verdict = await scorer.analyze(xssUrl);

  assert.equal(verdict.category, 'LOW_RISK');
  assert.equal(typeof verdict.summary, 'string');
  assert.equal(verdict.hostname, 'example.com');
});

test('Security: Protocol restrictions block file, blob, and javascript URIs', async () => {
  const scorer = new RiskScorer();

  const dangerousProtocols = [
    'javascript:alert(document.cookie)',
    'data:text/html,<script>alert(1)</script>',
    'file:///C:/Windows/System32/cmd.exe',
    'blob:https://example.com/uuid',
    'ftp://ftp.example.com'
  ];

  for (const uri of dangerousProtocols) {
    const verdict = await scorer.analyze(uri);
    assert.equal(verdict.safe, false, `Scheme ${uri} must never be reported safe`);
    assert.equal(verdict.category, 'ERROR');
  }
});

test('Security: Zero-tolerance for silent safe fallbacks on malformed URLs', async () => {
  const scorer = new RiskScorer();
  const badInputs = [
    '',
    null,
    undefined,
    '   ',
    'https://',
    'http://:80',
    'http://[invalid-ipv6'
  ];

  for (const bad of badInputs) {
    const verdict = await scorer.analyze(bad);
    assert.equal(verdict.safe, false, `Bad input ${bad} must not default to safe`);
    assert.equal(verdict.category, 'ERROR');
  }
});
