# PhishLens Web Shield: Privacy Specification & Data Handling Policy

**Version:** 1.1.0  
**Effective Date:** October 2026  
**Scope:** PhishLens Web Shield Browser Extension for Chromium-based Browsers  

---

## 1. Core Privacy Architecture

PhishLens Web Shield is designed under the **Privacy-by-Design** and **Data Minimization** principles (GDPR Art. 5, NIST SP 800-53). Unlike traditional cloud-based web reputation plugins that transmit every visited URL and full query string to remote corporate telemetry endpoints, PhishLens performs real-time inspection directly **on the client device (in-browser)**.

```
+-------------------------------------------------------------------------+
|                           CLIENT BROWSER (LOCAL)                        |
|                                                                         |
|  [Visited URL] ---> [Safe URL Parser] ---> [Feature Extractor]          |
|                                                    |                    |
|                                        +-----------+-----------+        |
|                                        |                       |        |
|                                [Heuristic Engine]       [ML Model (JS)] |
|                                        |                       |        |
|                                        +-----------+-----------+        |
|                                                    |                    |
|                                            [Risk Scorer]                |
|                                                    |                    |
|                                            [Local Decision]             |
+-------------------------------------------------------------------------+
                                                     |
                                (Zero Full URL Transmission)
```

---

## 2. Data Collection & Processing Details

### 2.1 Visited URLs and Query Strings
- **Processing Location:** Exclusively in local browser memory within the Manifest V3 Service Worker.
- **Remote Transmission:** **None.** Complete URLs, query parameters (which may contain session tokens, password reset hashes, or personal emails), path segments, and anchor fragments are **never sent** to any external server or API.
- **Persistence:** Analysis verdicts are temporarily retained in ephemeral in-memory session caches (`SessionManager`) strictly to prevent duplicate computation during redirect chains. Cache entries expire automatically after 5 minutes and are scrubbed immediately when the tab is closed (`chrome.tabs.onRemoved`).

### 2.2 Hostnames and Domain Names
- **Local Feature Extraction:** Hostnames are analyzed locally for character entropy, length, digit density, hyphen count, and edit distance against brand catalogs.
- **Threat Intelligence Lookups:**
  - By default, threat intelligence lookups query an **embedded local offline threat feed** (`LocalThreatIntelProvider`), requiring zero network traffic.
  - If an external threat intelligence provider adapter is optionally enabled by the user or organization, queries are strictly constrained to the **registrable domain or SHA-256 domain hash prefix**. Full URLs, paths, and query parameters are never included in threat intelligence requests.

### 2.3 User Identifiers & Telemetry
- PhishLens does not assign persistent user IDs, installation IDs, device fingerprints, or advertising trackers.
- No analytics SDKs (e.g., Google Analytics, Mixpanel, Sentry) are included in the extension bundle.

---

## 3. Permissions Justification (Least Privilege)

| Permission | Purpose & Scope | Privacy Impact |
|---|---|---|
| `webNavigation` | Required to intercept top-level navigation (`frameId === 0`) on `onBeforeNavigate` to protect users prior to page execution. | Does not collect or log history to disk; reads destination URL in memory for scanning only. |
| `tabs` | Required to update active tab destination to `popup/blocked.html` upon detecting high-risk sites and to clear session state when a tab is closed. | Scoped to navigation lifecycle management. |
| `storage` | Required to persist user configuration (custom threshold preferences, threat feed toggles). | Local extension storage only; not synced across accounts unless explicitly opted into Chrome sync. |
| `declarativeNetRequest` | Used to enforce network-level redirects for confirmed high-threat indicators and prevent navigation bypass exploits. | Operates declaratively via local dynamic rule tables. |
| `*://*/*` (Host Permission) | Necessary to evaluate URLs across all web domains and inject minimal notification banners on suspicious pages. | Required for extension core utility as a global web shield. |

---

## 4. User Consent & Controls

1. **Security Bypass Control:** When a site is blocked, users retain the explicit right to authorize a temporary session bypass ("Proceed Anyway"). Bypass grants are scoped strictly to the specific tab and domain for 10 minutes.
2. **Local Logging:** Diagnostic messages emitted via `console.log` are visible solely within Developer Tools and do not leave the local browser environment.
