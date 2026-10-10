/**
 * Homoglyph Normalization, Punycode Handling, and Brand Impersonation Detection
 */

// Common Cyrillic and Greek homoglyphs frequently used in IDN spoofing attacks
const HOMOGLYPH_MAP = {
  // Cyrillic to Latin
  'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't',
  'в': 'b', 'г': 'r', 'п': 'n',
  // Uppercase Cyrillic
  'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
  'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'У': 'Y',
  // Greek to Latin
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ν': 'v'
};

// Common leetspeak substitutions used in phishing
const LEET_MAP = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's'
};

// Curated list of high-value brands frequently targeted by phishing campaigns
export const HIGH_TARGET_BRANDS = [
  'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'ebay',
  'netflix', 'linkedin', 'twitter', 'instagram', 'github', 'reddit', 'youtube',
  'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'binance', 'coinbase',
  'steam', 'outlook', 'office365', 'dropbox', 'yahoo', 'whatsapp', 'telegram',
  'walmart', 'roblox', 'tiktok', 'discord', 'irs', 'usps', 'fedex', 'dhl'
];

/**
 * Normalizes Unicode homoglyphs to ASCII equivalents.
 * @param {string} text
 * @returns {string}
 */
export function normalizeHomoglyphs(text) {
  if (!text) return '';
  let result = '';
  for (const char of text) {
    result += HOMOGLYPH_MAP[char] || char;
  }
  return result;
}

/**
 * Normalizes leetspeak numbers/symbols to letters for fuzzy matching.
 * @param {string} text
 * @returns {string}
 */
export function normalizeLeetspeak(text) {
  if (!text) return '';
  let result = '';
  for (const char of text.toLowerCase()) {
    result += LEET_MAP[char] || char;
  }
  return result;
}

/**
 * Computes Levenshtein edit distance between two strings.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  if (!a || !b) return (a || b).length;
  if (a === b) return 0;

  const al = a.length;
  const bl = b.length;
  const matrix = Array.from({ length: bl + 1 }, () => new Array(al + 1).fill(0));

  for (let i = 0; i <= al; i++) matrix[0][i] = i;
  for (let j = 0; j <= bl; j++) matrix[j][0] = j;

  for (let j = 1; j <= bl; j++) {
    for (let i = 1; i <= al; i++) {
      if (b.charAt(j - 1) === a.charAt(i - 1)) {
        matrix[j][i] = matrix[j - 1][i - 1];
      } else {
        matrix[j][i] = Math.min(
          matrix[j - 1][i - 1] + 1, // substitution
          matrix[j][i - 1] + 1,     // insertion
          matrix[j - 1][i] + 1      // deletion
        );
      }
    }
  }

  return matrix[bl][al];
}

/**
 * Checks if a hostname or domain label is impersonating a known brand.
 * 
 * Returns an impersonation score in [0.0, 1.0]:
 * - 0.0: Exactly legitimate brand or completely unrelated domain.
 * - 0.5 - 1.0: Close typosquatting, homoglyph lookalike, or deceptive subdomain.
 * 
 * @param {string} domainLabel - The domain name label (e.g., "paypa1" from "paypa1.com")
 * @param {string} fullHostname - The full hostname (e.g., "login.paypal.com.attacker.com")
 * @returns {{
 *   score: number,
 *   impersonatedBrand: string | null,
 *   technique: string | null
 * }}
 */
export function detectImpersonation(domainLabel, fullHostname = '') {
  if (!domainLabel) {
    return { score: 0.0, impersonatedBrand: null, technique: null };
  }

  const cleanLabel = domainLabel.toLowerCase().trim();
  const cleanHost = fullHostname.toLowerCase().trim();

  // Step 1: Check if the registrable domain label IS exactly the brand (Legitimate!)
  if (HIGH_TARGET_BRANDS.includes(cleanLabel)) {
    return { score: 0.0, impersonatedBrand: cleanLabel, technique: 'legitimate_brand' };
  }

  // Step 2: Check for homoglyph / IDN attacks on the domain label
  const dehomoglyphed = normalizeHomoglyphs(cleanLabel);
  if (dehomoglyphed !== cleanLabel && HIGH_TARGET_BRANDS.includes(dehomoglyphed)) {
    return {
      score: 1.0,
      impersonatedBrand: dehomoglyphed,
      technique: 'homoglyph_attack'
    };
  }

  // Step 3: Check for leetspeak lookalikes (e.g., paypa1, g00gle)
  const deleeted = normalizeLeetspeak(dehomoglyphed);
  if (deleeted !== cleanLabel && HIGH_TARGET_BRANDS.includes(deleeted)) {
    return {
      score: 0.95,
      impersonatedBrand: deleeted,
      technique: 'leetspeak_typosquat'
    };
  }

  // Step 4: Check edit distance & combosquatting against known brands
  let bestScore = 0.0;
  let targetBrand = null;
  let technique = null;

  for (const brand of HIGH_TARGET_BRANDS) {
    // Check direct edit distance on label and normalized versions
    const dist = Math.min(
      levenshteinDistance(cleanLabel, brand),
      levenshteinDistance(deleeted, brand)
    );
    if (dist > 0 && dist <= 2 && Math.abs(cleanLabel.length - brand.length) <= 2) {
      const score = dist === 1 ? 0.90 : 0.70;
      if (score > bestScore) {
        bestScore = score;
        targetBrand = brand;
        technique = 'edit_distance_typosquat';
      }
    }

    // Check combosquatting on original label and normalized/deleeted label
    // e.g. "paypa1-security" or "paypal-update"
    const candidates = [cleanLabel, deleeted];
    for (const cand of candidates) {
      if (cand.includes(brand) && cand !== brand) {
        if (cand.startsWith(`${brand}-`) || cand.endsWith(`-${brand}`) || cand.includes(`-${brand}-`) || cand.includes(brand)) {
          const score = cand === cleanLabel ? 0.85 : 0.90; // higher if leetspeak was also used
          if (score > bestScore) {
            bestScore = score;
            targetBrand = brand;
            technique = cand === cleanLabel ? 'combosquatting' : 'leetspeak_combosquatting';
          }
        }
      }
    }
  }

  // Step 5: Subdomain deception check (e.g., "paypal.com.attacker.com")
  if (cleanHost && bestScore < 0.8) {
    for (const brand of HIGH_TARGET_BRANDS) {
      // If brand is in subdomain but NOT in registrable domain label
      if (cleanHost.includes(`${brand}.`) && !cleanLabel.includes(brand)) {
        if (0.85 > bestScore) {
          bestScore = 0.85;
          targetBrand = brand;
          technique = 'subdomain_deception';
        }
      }
    }
  }

  return {
    score: bestScore,
    impersonatedBrand: targetBrand,
    technique
  };
}
