# PhishLens Web Shield: Architecture Specification

## 1. High-Level System Architecture

PhishLens Web Shield is implemented as a modern **Chromium Manifest V3 (MV3)** browser extension. It decouples high-speed local heuristic rules, on-device machine learning inference, and threat intelligence into a resilient, asynchronous detection pipeline.

```mermaid
flowchart TD
    subgraph BrowserLifecycle ["Browser Navigation Lifecycle"]
        UserNav["User Enters URL / Clicks Link"] --> WN_Before["chrome.webNavigation.onBeforeNavigate"]
        WN_Before --> CheckBypass{"Session Bypassed?"}
        CheckBypass -->|Yes| AllowPass["Allow Navigation"]
        CheckBypass -->|No| CacheCheck{"In Session Cache?"}
        CacheCheck -->|Hit| Verdict["Apply Cached Verdict"]
        CacheCheck -->|Miss| Scorer["RiskScorer Pipeline"]
    end

    subgraph DetectionPipeline ["Detection Pipeline"]
        Scorer --> URLP["Safe URL Parser / PSL"]
        URLP --> FE["Feature Extractor - 12 Features"]
        FE --> HE["Heuristic Engine - 12 Rules"]
        FE --> ML["ML Engine - Logistic Regression"]
        URLP --> TI["Threat Intel Manager - Local Cache"]
        HE --> RiskAgg["Risk Aggregator & Calibrator"]
        ML --> RiskAgg
        TI --> RiskAgg
        RiskAgg --> FinalVerdict["Classification Result"]
    end

    subgraph EnforcementUI ["Enforcement & UI Presentation"]
        FinalVerdict --> DecisionBranch{"Verdict Category"}
        DecisionBranch -->|HIGH_RISK| BlockPage["Redirect tab to popup/blocked.html"]
        DecisionBranch -->|SUSPICIOUS| PostNav["onCommitted Notice Banner via content.js"]
        DecisionBranch -->|LOW_RISK| Quiet["Action Badge Checkmark"]
        
        BlockPage -->|User clicks Proceed Anyway| GrantBypass["sessionManager.grantBypass"]
        GrantBypass --> Reload["window.location.replace URL"]
    end
```

---

## 2. Component Breakdown

### 2.1 Manifest V3 Service Worker (`background.js`)
Unlike Manifest V2 persistent background pages, MV3 service workers are **event-driven and ephemeral**, terminating automatically after ~30 seconds of inactivity.

PhishLens addresses worker ephemerality through:
1. **Asynchronous Model Preloading (`modelInitPromise`):** When the service worker awakens, it initiates an asynchronous fetch of `model/phishing_model.json`. All incoming navigation and runtime message handlers await `modelInitPromise` before running inference, eliminating uninitialized model states.
2. **Session Storage Mirroring (`SessionManager`):** Analysis results and user-authorized bypass tokens are stored in an in-memory LRU cache with configurable TTLs (5 minutes for analysis, 10 minutes for bypass grants).
3. **Declarative Network Request (`declarativeNetRequest`):** Dynamic DNR rules are registered for verified high-confidence threat feed hits, allowing the browser network layer to intercept requests before socket creation.

### 2.2 Public Suffix List & Domain Parsing (`src/utils/psl.js`)
Decomposes complex hostnames into:
- **`registrableDomain` (eTLD+1):** The effective domain purchased by a registrant (e.g., `attacker.co.uk` from `login.paypal.com.attacker.co.uk`).
- **`subdomain`:** Labels preceding the registrable domain.
- **`publicSuffix`:** Multi-part or single-part TLD (`co.uk`, `com`, `github.io`).
- **`isIP`:** Strict IPv4 (range [0, 255]) and IPv6 validation.

### 2.3 Homoglyph & Impersonation Engine (`src/utils/homoglyphs.js`)
Mitigates internationalized domain name (IDN) and visual lookalike deception:
- Dehomoglyphs Cyrillic, Greek, and Latin lookalikes.
- Normalizes leetspeak numeric substitutions (`0` -> `o`, `1` -> `l`, `3` -> `e`).
- Computes Levenshtein edit distance and combosquatting patterns against high-value target brand dictionaries.

### 2.4 Safe URL Parser (`src/engine/urlParser.js`)
- Enforces strict scheme whitelisting (`http:` and `https:`).
- Throws typed errors (`MalformedURLError`, `UnsupportedSchemeError`) on unsupported schemes (`javascript:`, `data:`, `file:`, `chrome:`).
- Detects the `@` credential trick in the URL **authority/userinfo component** (`https://user:pass@evil.com/`) while explicitly ignoring `@` in query parameters.

### 2.5 Feature Extractor (`src/engine/featureExtractor.js`)
Extracts 12 deterministic features:
1. `urlLength_normalized`: Total URL character length / 100.
2. `numDots_normalized`: Dot separators in hostname / 5.
3. `numHyphens_normalized`: Hyphens in hostname / 5.
4. `hasIP`: Binary indicator for raw numeric IP hosts.
5. `hasHTTPS`: Binary indicator for TLS transport.
6. `hasSuspiciousTLD`: Binary indicator for abuse-heavy TLD extensions.
7. `numSpecialChars_normalized`: Special characters (`@`, `&`, `=`, `_`, `?`) in URL / 10.
8. `domainEntropy_normalized`: Shannon character entropy of hostname / 5.
9. `typosquattingScore`: Calibrated brand impersonation similarity [0.0, 1.0].
10. `numDigits_normalized`: Numeric characters in hostname / 10.
11. `hostnameLength_normalized`: Hostname length / 50.
12. `hasAtSymbol`: Binary indicator for userinfo authority obfuscation.

### 2.6 Heuristic Engine (`src/engine/heuristicEngine.js`)
Applies deterministic cybersecurity rules returning an aggregate score (0–100) and structured risk reason objects with assigned severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

### 2.7 Machine Learning Engine (`src/engine/mlEngine.js`)
Executes logistic regression inference on the 12 normalized features:
$$z = \mathbf{w} \cdot \mathbf{x} + b$$
$$P(\text{phishing}) = \frac{1}{1 + e^{-z}}$$
Distinguishes probability from thresholded classification and provides graceful fallback when the model configuration is unavailable.

### 2.8 Threat Intelligence Coordinator (`src/engine/threatIntelligence.js`)
Coordinates reputation feeds using a provider interface (`BaseThreatIntelProvider`).
- Default: `LocalThreatIntelProvider` (offline signatures).
- Bounded LRU cache with TTL expiration (default 10 minutes).
- Asynchronous timeout wrappers (2000ms default) ensuring that failing external providers never freeze navigation or crash the extension.

### 2.9 Risk Aggregator (`src/engine/riskScorer.js`)
Synthesizes the pipeline components:
- Combines ML probability (45% weight) and Heuristic score (55% weight).
- Applies safety overrides for critical heuristic findings (minimum risk 70).
- Enforces strict threat intelligence overrides (score 95 for confirmed malicious feeds).
- Categorizes verdicts into `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, or `ERROR`.
- **Never reports an analysis failure as safe.**
- **Never claims a URL is guaranteed legitimate merely because no threat was detected.**

---

## 3. Session Bypass & Loop Elimination Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser as Chrome Browser
    participant SW as background.js (Service Worker)
    participant SM as SessionManager
    participant BlockedPage as popup/blocked.html

    User->>Browser: Enters phishing URL (e.g. paypa1-update.xyz)
    Browser->>SW: onBeforeNavigate event
    SW->>SM: isBypassed(tabId, url)?
    SM-->>SW: false
    SW->>SW: riskScorer.analyze(url) -> HIGH_RISK (Score 88)
    SW->>Browser: chrome.tabs.update -> popup/blocked.html?url=...
    Browser->>BlockedPage: Renders Warning UI
    
    Note over User,BlockedPage: User reviews warning and decides to proceed
    User->>BlockedPage: Clicks "Proceed Anyway"
    BlockedPage->>SW: chrome.runtime.sendMessage({ action: 'grantBypass', url })
    SW->>SM: grantBypass(tabId, url, 10 min TTL)
    SW-->>BlockedPage: { success: true }
    BlockedPage->>Browser: window.location.replace(url)
    
    Browser->>SW: onBeforeNavigate event (Second Navigation)
    SW->>SM: isBypassed(tabId, url)?
    SM-->>SW: true (Bypass Active!)
    SW->>Browser: Allow navigation to proceed without redirect
    Note over Browser: User accesses page with Warning Badge
```
