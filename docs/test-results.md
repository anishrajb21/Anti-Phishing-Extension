# PhishLens Web Shield: Automated Test Results & Benchmark Report

## 1. Test Suite Summary

**Execution Environment:** Node.js v24.16.0, Python 3.13.13, Windows 11  
**Test Runners:** `node:test` (Native JavaScript Runner), `pytest` 9.1.1 (Python ML Runner)  
**Total Automated Tests:** 28 passing / 0 failing  

| Test Suite | File | Tests | Status | Duration |
|---|---|---|---|---|
| **JavaScript Unit Tests** | `tests/unit/engine.test.js` | 9 | **PASS** | ~2.1s |
| **JavaScript Security Tests** | `tests/security/security.test.js` | 8 | **PASS** | ~0.8s |
| **JavaScript Model Parity** | `tests/unit/model_parity.test.js` | 1 | **PASS** | ~4.2ms |
| **JavaScript Integration Tests** | `tests/integration/integration.test.js` | 4 | **PASS** | ~2.5s |
| **Python ML Pipeline Tests** | `ml/tests/test_ml_pipeline.py` | 6 | **PASS** | ~1.7s |
| **Total Combined** | | **28** | **ALL PASS** | |

---

## 2. JavaScript Test Suite Details

### 2.1 Unit Tests (`tests/unit/engine.test.js`)
- `PSL Domain Parser correctly decomposes standard and multi-part domains` (PASS)
- `Homoglyph and Impersonation Detector identifies attacks` (PASS)
- `URL Parser enforces supported schemes and rejects malformed URLs` (PASS)
- `Feature Extractor produces bounded normalized vector and metadata` (PASS)
- `Heuristic Engine produces structured reasons and calibrated scores` (PASS)
- `ML Engine handles model loading, inference, and uninitialized state safely` (PASS)
- `Threat Intelligence Manager supports caching, provider queries, and graceful fallbacks` (PASS)
- `Risk Scorer categorizes risk without claiming definitive safety` (PASS)
- `Session Manager maintains cache and prevents redirect loops via bypass allowlist` (PASS)

### 2.2 Security Tests (`tests/security/security.test.js`)
- `Security: Obfuscation with User-Info (@) authority is flagged as Critical` (PASS)
- `Security: Query parameter containing email with @ does NOT trigger false positive authority flag` (PASS)
- `Security: Punycode and IDN Homoglyph Spoofing is detected` (PASS)
- `Security: Subdomain Brand Mimicry is caught on attacker registrable domain` (PASS)
- `Security: Non-standard ports are penalized` (PASS)
- `Security: Injection strings in URLs do not cause exceptions and are safely parsed` (PASS)
- `Security: Protocol restrictions block file, blob, and javascript URIs` (PASS)
- `Security: Zero-tolerance for silent safe fallbacks on malformed URLs` (PASS)

### 2.3 Integration Tests (`tests/integration/integration.test.js`)
- `Integration: End-to-end detection pipeline with real exported model` (PASS)
- `Integration: Threat Intelligence provider failures and timeouts degrade gracefully` (PASS)
- `Integration: Session Manager caching, expiration, and navigation bypass prevention` (PASS)
- `Integration: Verdict contract matches all UI data binding requirements` (PASS)

### 2.4 Model Parity Tests (`tests/unit/model_parity.test.js`)
- `Model Parity: phishing_model.json is valid and loadable by MLEngine` (PASS)

---

## 3. Machine Learning Benchmark & Evaluation

**Evaluation Script:** `python ml/evaluate_model.py`  
**Model Type:** Calibrated Logistic Regression (`model/phishing_model.json`)  
**Tuned Decision Threshold:** 0.42  

### Held-out Test Set & Full Benchmark Metrics:
- **Total Samples:** 80 URLs (40 Legitimate Tranco/Open, 40 Verified/Synthetic Phishing Lures)
- **Precision:** 1.0000 (100% precision on flagged sites)
- **Recall:** 0.9750 (97.5% detection rate)
- **F1-Score:** 0.9873
- **False Positive Rate (FPR):** 0.0000 (0.0% false positives on legitimate sample set)
- **False Negative Rate (FNR):** 0.0250 (2.5%)
- **ROC-AUC:** 0.9994
- **PR-AUC:** 0.9994

### Confusion Matrix:
| | Predicted Negative (Legit) | Predicted Positive (Phish) |
|---|---|---|
| **Actual Negative** | 40 (TN) | 0 (FP) |
| **Actual Positive** | 1 (FN) | 39 (TP) |
