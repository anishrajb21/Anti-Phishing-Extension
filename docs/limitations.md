# PhishLens Web Shield: Engineering Limitations & Security Boundaries

## 1. Scope of Client-Side URL Analysis

PhishLens Web Shield provides **first-line, on-device perimeter filtering** by inspecting URL syntax, domain typography, registrable domain structure, and local threat signatures. While highly efficient and privacy-preserving, client-side URL analysis possesses known theoretical and operational boundaries.

### What PhishLens CAN Detect:
- Brand impersonation in domain labels (`paypa1.com`, `paypal-security.com`).
- Homoglyph and Punycode spoofing (`xn--...`).
- Subdomain deception (`brand.com.untrusted.net`).
- Authority / Credential hiding tricks (`https://brand.com@evil.com`).
- High-risk / disposable TLDs and direct IP-hosted portals.
- Algorithmically generated domains (high Shannon entropy).
- Known malicious domains listed in local or cached threat intelligence.

### What PhishLens CANNOT Conclusively Detect from URL Syntax Alone:
1. **Compromised Legitimate Hosts:** If an attacker uploads a credential-harvesting phishing form to an authentic, high-reputation domain (e.g. `compromised-legitimate-firm.com/contact/login.php`), the URL syntax itself will appear benign.
2. **Dynamic DOM Manipulation & In-Memory Cloaking:** PhishLens analyzes navigation targets before content execution. It does not inspect rendered DOM trees, CSS styling, or JavaScript obfuscation payloads executing inside the page.
3. **Phishing Inside Legitimate Cloud Services:** Phishing pages hosted on legitimate application platforms (e.g., Google Forms, Microsoft Forms, Notion, Airtable, Firebase App) cannot be blocked by domain-level heuristics without causing widespread false positives for legitimate users of those platforms.
4. **Zero-Day Lookalike Brands:** New or niche brand names not present in the curated target dictionary (`HIGH_TARGET_BRANDS`) will not trigger targeted combosquatting or typosquatting rules unless caught by generic entropy, TLD, or length indicators.

---

## 2. False Positive vs. False Negative Tradeoffs

- **Detection Threshold Selection:** The decision threshold is tuned on validation data to maintain a **False Positive Rate (FPR) <= 0.05** on legitimate domains. Increasing sensitivity to catch subtle lures increases the likelihood of flagging benign domains that use hyphens or unusual subdomains.
- **Transport Security (HTTPS):** Over 85% of modern phishing websites utilize valid TLS certificates (via automated certificate authorities like Let's Encrypt). PhishLens notes unencrypted HTTP transport as an informational indicator (+10 risk), but **never treats HTTPS as proof of legitimacy**.
- **Absence of Malicious Indicators:** PhishLens explicitly distinguishes between a site having a *low risk score* and being *guaranteed safe*. A verdict of `LOW_RISK` signifies that no adverse heuristics or signatures were detected; it is never a cryptographic guarantee of safety.

---

## 3. Platform & Browser Constraints (Manifest V3)

1. **Non-Blocking Navigation Listeners:** In Manifest V3, `chrome.webNavigation.onBeforeNavigate` is an asynchronous notification. While PhishLens issues immediate redirects for high-risk URLs, a short network race window exists before the redirect commits. PhishLens leverages `declarativeNetRequest` dynamic rules where possible to mitigate this window.
2. **Service Worker Lifecycle:** Service workers are paused after periods of inactivity. While model loading and state hydration are handled gracefully via `modelInitPromise` and `SessionManager`, initial wake-up adds ~5–15ms of latency to the first navigation event following an idle period.
3. **DeclarativeNetRequest Quotas:** Chromium imposes hard quotas on dynamic declarativeNetRequest rules (typically 5,000–30,000 rules depending on browser version). PhishLens uses dynamic rules selectively for confirmed threats rather than attempting to load full multi-million-domain blocklists into browser memory.
