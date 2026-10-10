import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MLEngine } from '../../src/engine/mlEngine.js';
import { extractFeatures } from '../../src/engine/featureExtractor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODEL_FILE_PATH = path.resolve(__dirname, '../../model/phishing_model.json');

test('Model Parity: phishing_model.json is valid and loadable by MLEngine', () => {
  assert.ok(fs.existsSync(MODEL_FILE_PATH), 'phishing_model.json must exist');
  const rawJson = fs.readFileSync(MODEL_FILE_PATH, 'utf-8');
  const modelConfig = JSON.parse(rawJson);

  assert.equal(modelConfig.modelType, 'logistic_regression');
  assert.ok(Array.isArray(modelConfig.weights));
  assert.equal(typeof modelConfig.bias, 'number');
  assert.equal(modelConfig.weights.length, 12);
  assert.equal(modelConfig.features.length, 12);

  const engine = new MLEngine(modelConfig);
  assert.equal(engine.isLoaded, true);

  // Test inference on legitimate URL
  const legitFeatures = extractFeatures('https://www.google.com/search?q=cybersecurity');
  const legitPred = engine.predict(legitFeatures.normalized);
  assert.equal(legitPred.available, true);
  assert.equal(legitPred.status, 'SUCCESS');
  assert.ok(legitPred.probability < 0.40, `Legitimate site should have low phishing prob, got ${legitPred.probability}`);

  // Test inference on spoofed URL
  const spoofFeatures = extractFeatures('https://paypa1-security-verification.xyz/login');
  const spoofPred = engine.predict(spoofFeatures.normalized);
  assert.equal(spoofPred.available, true);
  assert.ok(spoofPred.probability > 0.50, `Spoofed site should have elevated phishing prob, got ${spoofPred.probability}`);
});
