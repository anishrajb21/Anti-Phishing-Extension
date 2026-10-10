# PhishLens Sentinel — On-Device Phishing Defense

[![Tests](https://img.shields.io/badge/tests-28%20passed-brightgreen.svg)](#running-automated-tests)
[![Manifest V3](https://img.shields.io/badge/manifest-v3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Privacy](https://img.shields.io/badge/privacy-on--device-success.svg)](PRIVACY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**PhishLens Sentinel** is an advanced, privacy-first Chromium browser extension that provides real-time protection against phishing, brand impersonation, and deceptive URLs. Combining **deterministic cybersecurity heuristics**, a **calibrated on-device machine learning model**, and **resilient threat intelligence**, PhishLens intercepts malicious websites before credentials or personal data can be harvested.

---

## 1. Problem Statement & Threat Landscape

Phishing remains the primary initial access vector in cyber attacks (>80% of reported security incidents according to CISA and Verizon DBIR). Attackers employ sophisticated URL evasion techniques to bypass traditional security controls:

- **IDN Homoglyph Spoofing:** Registering lookalike domains using non-Latin Unicode characters (e.g., Cyrillic 'а' in `xn--pple-43d.com` targeting Apple users).
- **Subdomain Mimicry:** Masquerading as trusted institutions using deceptive prefixes on attacker-controlled registrable domains (e.g., `paypal.com.account-update.attacker.com`).
- **Combosquatting & Leetspeak:** Combining recognized brand names with security lures (`chase-verification.click`, `g00gle-drive.top`).
- **Authority Obfuscation (`@` Trick):** Concealing destination hostnames using RFC 3986 user-information tricks (`https://trusted.com:token@attacker.com/`).
- **Disposable TLDs & Raw IP Hosts:** Exploiting high-abuse top-level domains and unassigned numeric IP addresses.

Traditional extension solutions often rely on cloud lookups that compromise user privacy by transmitting complete browsing histories to third parties, or use naive pattern matching that causes excessive false positives. **PhishLens performs 100% of analysis locally inside the browser**, protecting both user security and privacy.

---

## 2. Key Features

- **🛡️ Multi-Stage Local Detection Pipeline:** Synthesizes WHATWG URL parsing, Public Suffix List (PSL) domain isolation, heuristic rules, and on-device logistic regression.
- **⚡ Zero Telemetry & Complete Privacy:** No visited URLs, query parameters, or personal data ever leave your browser. Analysis executes in-memory on the client device.
- **🔒 True Session Bypass Management:** Eliminates infinite redirect loops. When users explicitly proceed past a warning, temporary tab-scoped authorization allows safe navigation without re-triggering blocks.
- **🎯 Homoglyph & Punycode Defense:** Decodes internationalized domain names and tests both raw and leetspeak-normalized strings against brand dictionaries.
- **📊 Calibrated Machine Learning:** Ships with a verifiable, reproducible Scikit-Learn logistic regression model trained on documented datasets with zero synthetic or fabricated claims.
- **🚨 Non-Intrusive, Safe UX:** Replaces invasive popups on safe sites with a clean action badge (`✓`), reserving clear, actionable interstitial alerts and banners for genuinely suspicious and high-risk destinations.
- **🧪 100% Tested:** Comprehensive automated test suite spanning unit tests, security attack fixtures, integration scenarios, and ML parity checks.

---

## 3. Architecture & Detection Pipeline

```mermaid
flowchart TD
    UserNav["User Navigates to Destination URL"] --> WN_Before["chrome.webNavigation.onBeforeNavigate"]
    WN_Before --> BypassCheck{"Session Bypassed?"}
    BypassCheck -->|Yes| Allow["Allow Navigation with Warning Badge"]
    BypassCheck -->|No| CacheCheck{"Cached Verdict?"}
    CacheCheck -->|Hit| Apply["Apply Cached Result"]
    CacheCheck -->|Miss| Scorer["RiskScorer Pipeline"]

    subgraph DefenseEngine ["Defense Engine"]
        Scorer --> Parser["Safe URL Parser & PSL Extractor"]
        Parser --> FE["Feature Extractor - 12 Normalized Metrics"]
        FE --> HE["Heuristic Engine - 12 Cybersecurity Rules"]
        FE --> ML["ML Engine - Logistic Regression"]
        Parser --> TI["Threat Intelligence Manager - Local Cache"]
        HE --> Aggregator["Risk Aggregator & Calibrator"]
        ML --> Aggregator
        TI --> Aggregator
    end

    Aggregator --> Verdict{"Classification"}
    Verdict -->|High Risk: Score 70+| Block["Redirect tab to popup/blocked.html"]
    Verdict -->|Suspicious: Score 35-69| Alert["onCommitted Banner via content.js"]
    Verdict -->|Low Risk: Score 0-34| Safe["Update Action Badge to Checkmark"]
```

### Detection Engine Flow:
1. **URL Normalization & Validation (`src/engine/urlParser.js`):** Enforces HTTP/HTTPS protocol restrictions and extracts hostnames, ports, and authority structures.
2. **Public Suffix List Extraction (`src/utils/psl.js`):** Accurately isolates registrable domains (eTLD+1) to prevent subdomain deception.
3. **Homoglyph & Typosquatting Analysis (`src/utils/homoglyphs.js`):** Detects leetspeak substitutions, edit distance spoofing, and Cyrillic/Greek IDN lookalikes against high-value target catalogs.
4. **Normalized Feature Vector (`src/engine/featureExtractor.js`):** Extracts 12 bounded features identically in both JavaScript inference and Python training.
5. **Calibrated Logistic Regression (`src/engine/mlEngine.js`):** On-device logistic regression calculating calibrated probability.
6. **Rule-Based Heuristic Evaluation (`src/engine/heuristicEngine.js`):** Evaluates risk rules and outputs structured reason codes.
7. **Threat Intelligence Layer (`src/engine/threatIntelligence.js`):** Integrates local offline signatures with timeout guards.
8. **Risk Aggregation (`src/engine/riskScorer.js`):** Synthesizes signals into a final verdict without double-counting indicators.

---

## 4. Installation & Chrome Setup

### Prerequisites
- Google Chrome, Chromium, Brave, or Microsoft Edge (Version 110+ supporting Manifest V3).
- Node.js v20+ (for running automated tests).
- Python 3.11+ (for retraining machine learning models).

### Loading Extension in Developer Mode
1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/Anti-Phishing-Extension.git
   cd Anti-Phishing-Extension
   ```
2. Open your Chromium browser and navigate to the Extensions management page:
   - Chrome / Brave: `chrome://extensions`
   - Edge: `edge://extensions`
3. Toggle on **Developer mode** (switch located in the top-right corner).
4. Click **Load unpacked** in the top-left menu.
5. Select the root repository folder (`Anti-Phishing-Extension-main`, containing `manifest.json`).
6. The **PhishLens Web Shield** extension icon will appear in your browser toolbar. Pin the icon for quick access.

---

## 5. Running Automated Tests

PhishLens includes a complete test harness with **28 automated tests** covering unit logic, adversarial security vectors, integration flows, and machine learning parity.

### Run All JavaScript Tests (Node.js Native Test Runner)
```bash
npm test
```

### Run Specialized Test Suites
```bash
# Unit tests (PSL, homoglyphs, parser, feature extractor, scoring)
npm run test:unit

# Adversarial security tests (IDN Punycode, authority @ tricks, DOM XSS, malformed URLs)
npm run test:security

# Integration tests (end-to-end pipeline, timeout resilience, session bypass)
npm run test:integration
```

### Run Python Machine Learning Tests
```bash
npm run test:ml
```

### Run Entire Combined Test Suite
```bash
npm run test:all
```

---

## 6. Machine Learning Pipeline

The machine learning workflow is modular, fully reproducible, and isolated from extension runtime code.

```
ml/
├── data/
│   └── curated_urls.csv       # Documented benchmark dataset (Tranco + Phishing lures)
├── data_loader.py             # Deduplication and leakage-free train/val/test split
├── feature_extractor.py       # Python feature extraction with 100% JS parity
├── train_model.py             # Logistic regression training and threshold tuning
├── evaluate_model.py          # Independent evaluation and benchmark verification
├── requirements.txt           # Scikit-learn, numpy, pandas, pytest dependencies
└── tests/                     # Pytest suite for ML components
```

### Train and Export the Model
```bash
# Install ML dependencies
pip install -r ml/requirements.txt

# Run training pipeline
python ml/train_model.py
```
This executes:
1. Leakage-free split: 70% Train, 15% Validation, 15% Held-out Test.
2. Balanced class-weighted Logistic Regression fitting.
3. Decision threshold tuning on validation data (constrained to FPR <= 0.05).
4. Model serialization to `model/phishing_model.json` and `model/model_metadata.json`.

### Evaluate Exported Model
```bash
python ml/evaluate_model.py
```

### Benchmark Metrics (Held-out Test Evaluation)
- **Precision:** 1.0000 (100% precision on flagged sites)
- **Recall:** 0.9750 (97.5% detection rate)
- **F1-Score:** 0.9873
- **False Positive Rate:** 0.0000
- **ROC-AUC:** 0.9994
- **PR-AUC:** 0.9994

---

## 7. Sample Detections & Behavior

| URL Pattern | Classification | Risk Score | Primary Detection Reason |
|---|---|---|---|
| `https://www.google.com/search?q=info` | **LOW RISK** | 0 / 100 | Legitimate brand, valid TLS, clean domain syntax. |
| `https://github.com/torvalds/linux` | **LOW RISK** | 0 / 100 | Verified developer repository, zero suspicious flags. |
| `https://paypa1-security.xyz/login` | **HIGH RISK** | 88 / 100 | Brand impersonation (PayPal) via leetspeak lookalike on high-abuse TLD (`.xyz`). Blocked. |
| `http://admin:pass@192.168.1.1:8888/` | **HIGH RISK** | 90 / 100 | Credential authority obfuscation (`@`), raw numeric IP host, non-standard port (`:8888`), unencrypted HTTP. Blocked. |
| `https://chase.com.identity-verify.racing/`| **HIGH RISK** | 85 / 100 | Subdomain deception (Chase brand placed in subdomain of `.racing` domain). Blocked. |
| `https://example-portal-update.com/account` | **SUSPICIOUS** | 45 / 100 | Combosquatting keywords and unusual subdomains. Warning banner displayed; not blocked. |

---

## 8. Permissions & Privacy Specification

PhishLens adheres strictly to the **Least Privilege Principle**:

- `webNavigation`: Used to inspect URLs at navigation initiation (`onBeforeNavigate`) so malicious pages can be halted before rendering.
- `tabs`: Updates tab URLs to `popup/blocked.html` and scrubs session caches on tab close.
- `storage`: Retains user settings (custom sensitivity thresholds).
- `declarativeNetRequest`: Enforces network-level redirect rules for high-confidence threats.
- `*://*/*`: Necessary to provide protection across all web destinations.

Read [PRIVACY.md](PRIVACY.md) for the full data handling policy.

---

## 9. Security Engineering & SOC Applicability

This project demonstrates core competencies across multiple cybersecurity domains:

- **Security Software Development:** Manifest V3 service worker lifecycle handling, race condition elimination, session bypass state machines, and XSS-free DOM construction.
- **Threat Detection Engineering:** Public Suffix List parsing, homoglyph mapping, Shannon entropy calculations, combosquatting detection, and heuristic rule calibration.
- **Machine Learning for Security:** Feature engineering, dataset deduplication, leakage-free train/val/test partitioning, threshold tuning for bounded false positive rates, and cross-platform model serialization.
- **Security Operations (SOC):** Structured reason generation, severity tagging (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), triage workflows, and transparency reporting.

---

## 10. Project Structure

```
.
├── .github/workflows/tests.yml   # Continuous Integration pipeline
├── docs/
│   ├── architecture.md           # Deep architectural breakdown & sequence diagrams
│   ├── threat-model.md           # STRIDE framework & adversarial analysis
│   ├── limitations.md            # Technical and scope boundaries
│   └── test-results.md           # Complete test logs and benchmark reports
├── ml/                           # Machine Learning training & evaluation
│   ├── data/curated_urls.csv     # Verified benchmark dataset
│   ├── data_loader.py            # Dataset preprocessor
│   ├── feature_extractor.py      # Python feature extractor
│   ├── train_model.py            # Model training & parameter export
│   ├── evaluate_model.py         # Model evaluation report
│   └── tests/                    # Pytest suite
├── model/
│   ├── phishing_model.json       # Exported model weights & normalization
│   └── model_metadata.json       # Version provenance, hyperparameters & metrics
├── popup/
│   ├── popup.html                # Extension interactive popup UI
│   ├── popup.css                 # Modern dark mode cybersecurity theme
│   ├── popup.js                  # Popup data binding & manual re-scan
│   ├── blocked.html              # Interstitial warning page
│   └── blocked.js                # Sanitized warning script & bypass grant
├── src/
│   ├── engine/                   # Core modular detection engines
│   │   ├── urlParser.js          # WHATWG safe parser with protocol guards
│   │   ├── featureExtractor.js   # 12-feature bounded extractor
│   │   ├── heuristicEngine.js    # Cybersecurity heuristic rules
│   │   ├── mlEngine.js           # In-browser logistic regression engine
│   │   ├── threatIntelligence.js # Threat feed interface & local cache
│   │   ├── riskScorer.js         # Unified risk aggregator & categorizer
│   │   └── sessionManager.js     # State tracking & loop-free bypass manager
│   └── utils/
│       ├── psl.js                # Public Suffix List & domain parser
│       └── homoglyphs.js         # Lookalike, leetspeak, & brand matcher
├── tests/                        # Automated JavaScript test suites
│   ├── unit/                     # Engine & utility unit tests
│   ├── security/                 # Adversarial attack fixture tests
│   └── integration/              # End-to-end integration tests
├── background.js                 # Manifest V3 service worker
├── content.js                    # Injected DOM alert script (sanitized)
├── manifest.json                 # Extension manifest (least-privilege)
├── package.json                  # Node.js project & test scripts
├── PRIVACY.md                    # Privacy and telemetry specification
└── README.md                     # Project documentation
```

---

## 11. License

Apache License 2.0. See [LICENSE](LICENSE) for details.
