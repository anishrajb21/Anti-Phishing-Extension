/**
 * Public Suffix List (PSL) & Registrable Domain (eTLD+1) Parser
 * Correctly identifies effective top-level domains to prevent subdomain spoofing.
 */

// Curated list of common multi-part public suffixes
const MULTI_PART_SUFFIXES = new Set([
  // United Kingdom
  'co.uk', 'org.uk', 'me.uk', 'net.uk', 'gov.uk', 'ac.uk', 'ltd.uk', 'plc.uk',
  // Australia
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  // Japan
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
  // Brazil
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'dev.br',
  // India
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'ac.in', 'res.in',
  // China & Hong Kong & Taiwan
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'org.tw', 'net.tw', 'edu.tw', 'gov.tw',
  // Canada, New Zealand, South Africa
  'gc.ca', 'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za',
  // Russia, Ukraine, Singapore, Malaysia
  'com.ru', 'net.ru', 'org.ru', 'com.ua', 'net.ua', 'org.ua',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  // Europe common
  'co.il', 'org.il', 'net.il', 'ac.il',
  'asso.fr', 'nom.fr',
  // Managed platforms / dynamic hosts
  'github.io', 'pages.dev', 'web.app', 'firebaseapp.com', 'netlify.app',
  'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com'
]);

/**
 * Parses a hostname into its components based on public suffixes.
 * @param {string} hostname - Domain hostname (e.g., "login.paypal.com.attacker.co.uk")
 * @returns {{
 *   hostname: string,
 *   subdomain: string,
 *   registrableDomain: string,
 *   domainLabel: string,
 *   publicSuffix: string,
 *   isIP: boolean
 * }}
 */
export function parseDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    return {
      hostname: '',
      subdomain: '',
      registrableDomain: '',
      domainLabel: '',
      publicSuffix: '',
      isIP: false
    };
  }

  const cleanHost = hostname.toLowerCase().trim().replace(/^\.+|\.+$/g, '');

  // Check IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipMatch = cleanHost.match(ipv4Regex);
  if (ipMatch) {
    const octets = ipMatch.slice(1, 5).map(Number);
    const validOctets = octets.every(o => o >= 0 && o <= 255);
    if (validOctets) {
      return {
        hostname: cleanHost,
        subdomain: '',
        registrableDomain: cleanHost,
        domainLabel: cleanHost,
        publicSuffix: '',
        isIP: true
      };
    }
  }

  // Check IPv6 (bracketed or plain)
  if (cleanHost.startsWith('[') || cleanHost.includes(':')) {
    return {
      hostname: cleanHost,
      subdomain: '',
      registrableDomain: cleanHost,
      domainLabel: cleanHost,
      publicSuffix: '',
      isIP: true
    };
  }

  const parts = cleanHost.split('.');
  if (parts.length === 1) {
    return {
      hostname: cleanHost,
      subdomain: '',
      registrableDomain: cleanHost,
      domainLabel: cleanHost,
      publicSuffix: '',
      isIP: false
    };
  }

  // Check if ending matches a multi-part suffix (e.g. co.uk)
  let publicSuffix = '';
  let registrableDomain = '';
  let subdomain = '';
  let domainLabel = '';

  if (parts.length >= 3) {
    const twoPartSuffix = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(twoPartSuffix)) {
      publicSuffix = twoPartSuffix;
      domainLabel = parts[parts.length - 3];
      registrableDomain = `${domainLabel}.${publicSuffix}`;
      subdomain = parts.slice(0, -3).join('.');
      return {
        hostname: cleanHost,
        subdomain,
        registrableDomain,
        domainLabel,
        publicSuffix,
        isIP: false
      };
    }
  }

  // Default: single-part suffix (e.g. .com, .org, .xyz)
  publicSuffix = parts[parts.length - 1];
  domainLabel = parts[parts.length - 2];
  registrableDomain = `${domainLabel}.${publicSuffix}`;
  subdomain = parts.slice(0, -2).join('.');

  return {
    hostname: cleanHost,
    subdomain,
    registrableDomain,
    domainLabel,
    publicSuffix,
    isIP: false
  };
}
