# PhishLens Web Shield: Threat Model & Security Specification

## 1. System Overview & Trust Boundaries

PhishLens Web Shield runs as a privileged browser extension within the user's web browser. It evaluates untrusted inputs (arbitrary URLs navigated by the user or triggered via web redirects) and protects the user against social engineering, credential harvesting, and malware delivery sites.

### Trust Boundaries
1. **Untrusted Web Content:** Any page rendered by the browser, including scripts, links, and DOM content controlled by external web servers.
2. **Untrusted Navigation URLs:** Incoming URL strings parsed from `chrome.webNavigation` events.
3. **Privileged Extension Context:** The background service worker (`background.js`), popup script (`popup.js`), and warning page (`blocked.js`).
4. **Intermediate Content Script (`content.js`):** Injected into untrusted web page DOM contexts. Operates in an isolated JavaScript world, but directly interacts with untrusted DOM elements.

---

## 2. STRIDE Threat Analysis

| Threat Category | Specific Threat Scenario | PhishLens Mitigation |
|---|---|---|
| **Spoofing** | **IDN / Homoglyph Domain Spoofing:** Attacker registers `xn--pple-43d.com` (Cyrillic 'а') to visually impersonate `apple.com`. | `src/utils/homoglyphs.js` maps Unicode homoglyphs to ASCII equivalents, flags Punycode `xn--` hosts, and compares normalized labels against target brands. |
| **Spoofing** | **Subdomain Brand Deception:** Attacker configures `paypal.com.account-update.attacker.com`. | `src/utils/psl.js` separates the registrable domain (`attacker.com`) from subdomains (`paypal.com.account-update`), detecting brand placement outside the registrable domain. |
| **Tampering** | **DOM Injection / XSS in Extension Banner:** Attacker constructs a malicious URL reflecting `<script>` tags into detection reason strings. | `content.js` and `blocked.js` exclusively use safe DOM APIs (`document.createElement`, `textContent`) and avoid `innerHTML` with unsanitized dynamic strings. |
| **Repudiation** | **False Claims of System Failure:** User or tester unable to determine why a site was permitted or blocked. | Structured verdicts return explicit detection reasons (`id`, `severity`, `title`, `description`) recorded in diagnostic logs. |
| **Information Disclosure** | **Browsing History Leaks via Remote APIs:** Extension transmits every visited domain/URL to external WHOIS or threat intelligence endpoints. | Complete URLs are never transmitted externally. Threat intelligence is handled locally by default; external lookups use domain-only queries. |
| **Denial of Service** | **Infinite Navigation Redirect Loops:** Blocking warning page repeatedly intercepts user navigation when user clicks "Proceed Anyway". | `SessionManager` implements tab- and URL-scoped bypass authorization with a 10-minute TTL, terminating redirect loops immediately. |
| **Elevation of Privilege** | **Unauthorized Extension Messaging:** Malicious web pages send spoofed messages to `chrome.runtime.onMessage` to manipulate extension state. | External web pages cannot invoke internal extension runtime listeners; `web_accessible_resources` are restricted. |

---

## 3. Evaluated Attack Vectors & Countermeasures

### 3.1 Authority / Credential Obfuscation (`@` Trick)
- **Vector:** RFC 3986 allows user information in the URL authority: `https://google.com:account@evil.com/login`. Vulnerable users see `google.com` and assume legitimacy, while the browser navigates to `evil.com`.
- **Countermeasure:** `urlParser.js` checks `urlObj.username` and `urlObj.password`. If present, `AUTHORITY_OBFUSCATION` is assigned `CRITICAL` severity (+30 heuristic risk), triggering a high-risk block. Legitimate `@` symbols inside query parameters (e.g. `?email=user@company.com`) are explicitly distinguished and not flagged.

### 3.2 Combosquatting & Leetspeak Typosquatting
- **Vector:** Attackers register variants combining legitimate brands with security lures (`paypal-security.com`, `g00gle-drive.top`).
- **Countermeasure:** `homoglyphs.js` tests both raw and leetspeak-normalized strings against a dictionary of high-risk brands. Hyphenated brand concatenations are assigned combosquatting penalties (+35 heuristic risk).

### 3.3 Numeric IP Address Hosts
- **Vector:** Attackers host phishing kits directly on raw IPv4/IPv6 addresses to avoid DNS takedowns: `http://192.168.1.1/login`.
- **Countermeasure:** Strict IPv4 octet validation and IPv6 detection assigns `RAW_IP_HOST` high severity (+25 heuristic risk).

### 3.4 Disposable / Abuse-Heavy TLDs
- **Vector:** Free or high-abuse TLDs (`.xyz`, `.top`, `.click`, `.download`) frequently host disposable phishing sites.
- **Countermeasure:** TLD suffix evaluation flags known high-abuse extensions (+15 heuristic risk), contributing to the cumulative risk score.

---

## 4. Residual Risks & Adversarial Evasion

1. **Legitimate Compromised Websites:** PhishLens analyzes URL structures and domain reputation. If an attacker compromises a legitimate, long-established domain (e.g. `university.edu/student/evil-form.html`), client-side URL features alone may evaluate the hostname as low risk.
2. **Post-Authentication Cloaking:** Phishing sites that serve a benign placeholder page until specific user-agent, IP, or geographic conditions are met cannot be fully unmasked without server-side crawler execution.
3. **Shortener Services:** URL shorteners (`bit.ly`, `tinyurl.com`) hide the final destination URL until the HTTP redirect occurs. PhishLens re-evaluates the destination upon navigation commit, but cannot inspect intermediate redirect hops pre-flight without external resolution.
