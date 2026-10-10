"""
Feature Extractor for URL Phishing Detection
Maintains exact parity with browser-side JavaScript feature extractor (src/engine/featureExtractor.js).
"""

import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
    'link', 'download', 'racing', 'party', 'science', 'stream',
    'club', 'loan', 'cam', 'country', 'buzz', 'rest', 'fit', 'guru'
}

HIGH_TARGET_BRANDS = [
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'ebay',
    'netflix', 'linkedin', 'twitter', 'instagram', 'github', 'reddit', 'youtube',
    'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'binance', 'coinbase',
    'steam', 'outlook', 'office365', 'dropbox', 'yahoo', 'whatsapp', 'telegram',
    'walmart', 'roblox', 'tiktok', 'discord', 'irs', 'usps', 'fedex', 'dhl'
]

HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'ѕ': 's', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't',
    'в': 'b', 'г': 'r', 'п': 'n',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ο': 'o',
    'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ν': 'v'
}

LEET_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
    '@': 'a', '$': 's'
}

FEATURE_NAMES = [
    'urlLength_normalized',
    'numDots_normalized',
    'numHyphens_normalized',
    'hasIP',
    'hasHTTPS',
    'hasSuspiciousTLD',
    'numSpecialChars_normalized',
    'domainEntropy_normalized',
    'typosquattingScore',
    'numDigits_normalized',
    'hostnameLength_normalized',
    'hasAtSymbol'
]


def normalize_homoglyphs(text: str) -> str:
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in text)


def normalize_leetspeak(text: str) -> str:
    return ''.join(LEET_MAP.get(c, c) for c in text.lower())


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    al, bl = len(a), len(b)
    matrix = [[0] * (al + 1) for _ in range(bl + 1)]
    for i in range(al + 1):
        matrix[0][i] = i
    for j in range(bl + 1):
        matrix[j][0] = j

    for j in range(1, bl + 1):
        for i in range(1, al + 1):
            if b[j - 1] == a[i - 1]:
                matrix[j][i] = matrix[j - 1][i - 1]
            else:
                matrix[j][i] = min(
                    matrix[j - 1][i - 1] + 1,
                    matrix[j][i - 1] + 1,
                    matrix[j - 1][i] + 1
                )
    return matrix[bl][al]


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_ip_host(hostname: str) -> bool:
    clean = hostname.strip().strip('.').lower()
    if clean.startswith('[') or ':' in clean:
        return True
    match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', clean)
    if match:
        octets = [int(o) for o in match.groups()]
        return all(0 <= o <= 255 for o in octets)
    return False


def detect_impersonation(domain_label: str, full_hostname: str) -> float:
    clean_label = domain_label.lower().strip()
    clean_host = full_hostname.lower().strip()

    if clean_label in HIGH_TARGET_BRANDS:
        return 0.0

    dehomoglyphed = normalize_homoglyphs(clean_label)
    if dehomoglyphed != clean_label and dehomoglyphed in HIGH_TARGET_BRANDS:
        return 1.0

    deleeted = normalize_leetspeak(dehomoglyphed)
    if deleeted != clean_label and deleeted in HIGH_TARGET_BRANDS:
        return 0.95

    best_score = 0.0
    for brand in HIGH_TARGET_BRANDS:
        dist = min(
            levenshtein_distance(clean_label, brand),
            levenshtein_distance(deleeted, brand)
        )
        if 0 < dist <= 2 and abs(len(clean_label) - len(brand)) <= 2:
            score = 0.90 if dist == 1 else 0.70
            best_score = max(best_score, score)

        for cand in [clean_label, deleeted]:
            if brand in cand and cand != brand:
                score = 0.85 if cand == clean_label else 0.90
                best_score = max(best_score, score)

    if clean_host and best_score < 0.8:
        for brand in HIGH_TARGET_BRANDS:
            if f"{brand}." in clean_host and brand not in clean_label:
                best_score = max(best_score, 0.85)

    return best_score


def extract_features_from_url(raw_url: str) -> dict:
    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or '').lower().strip()
    full_url = raw_url

    url_length = len(full_url)
    num_dots = hostname.count('.')
    num_hyphens = hostname.count('-')
    has_ip = 1 if is_ip_host(hostname) else 0
    has_https = 1 if parsed.scheme == 'https' else 0

    parts = hostname.split('.')
    suffix = parts[-1] if len(parts) > 1 else ''
    has_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0

    num_special_chars = len(re.findall(r'[@&=_?]', full_url))
    domain_entropy = calculate_entropy(hostname)

    domain_label = parts[-2] if len(parts) >= 2 else parts[0]
    typosquatting_score = detect_impersonation(domain_label, hostname)

    num_digits = len(re.findall(r'\d', hostname))
    hostname_length = len(hostname)
    has_at_symbol = 1 if bool(parsed.username or parsed.password) else 0

    raw = {
        'urlLength': url_length,
        'numDots': num_dots,
        'numHyphens': num_hyphens,
        'hasIP': has_ip,
        'hasHTTPS': has_https,
        'hasSuspiciousTLD': has_suspicious_tld,
        'numSpecialChars': num_special_chars,
        'domainEntropy': domain_entropy,
        'typosquattingScore': typosquatting_score,
        'numDigits': num_digits,
        'hostnameLength': hostname_length,
        'hasAtSymbol': has_at_symbol
    }

    normalized = [
        min(url_length / 100.0, 5.0),
        min(num_dots / 5.0, 5.0),
        min(num_hyphens / 5.0, 5.0),
        float(has_ip),
        float(has_https),
        float(has_suspicious_tld),
        min(num_special_chars / 10.0, 5.0),
        min(domain_entropy / 5.0, 5.0),
        float(typosquatting_score),
        min(num_digits / 10.0, 5.0),
        min(hostname_length / 50.0, 5.0),
        float(has_at_symbol)
    ]

    return {
        'raw': raw,
        'normalized': normalized,
        'feature_names': FEATURE_NAMES
    }
