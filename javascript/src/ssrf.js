'use strict';

const dns = require('dns').promises;
const { isValidUrl } = require('./validator');

/**
 * SSRF-hardening helpers: checking whether an IP or resolved hostname is
 * safe to let a server-side request reach.
 */

// IPv4 ranges considered private/reserved/non-routable for our purposes,
// including the 169.254.0.0/16 link-local block that covers the common
// cloud metadata SSRF target (169.254.169.254).
const IPV4_RANGES = [
  [/^127\./, 'loopback'],
  [/^10\./, 'private (RFC1918)'],
  [/^192\.168\./, 'private (RFC1918)'],
  [/^172\.(1[6-9]|2\d|3[01])\./, 'private (RFC1918)'],
  [/^169\.254\./, 'link-local'],
  [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, 'carrier-grade NAT (RFC6598)'],
  [/^0\./, 'unspecified/reserved'],
  [/^(22[4-9]|23\d)\./, 'multicast'],
];

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateOrReservedIp(ip) {
  if (ip.includes(':')) {
    // IPv6: cover loopback, link-local, and unique-local (ULA) ranges.
    const lower = ip.toLowerCase();
    return (
      lower === '::1' ||
      lower.startsWith('fe80:') ||
      lower.startsWith('fc') ||
      lower.startsWith('fd')
    );
  }
  return IPV4_RANGES.some(([re]) => re.test(ip));
}

/**
 * Reports whether url is an absolute http(s) URL whose hostname resolves
 * (via DNS) to at least one address, all of which are public.
 *
 * This performs a real DNS lookup and is therefore not a pure/fast check
 * like isValidUrl() -- use that first for cheap structural rejection, and
 * this only when about to make a server-side request to a caller-supplied
 * URL.
 *
 * Caveat: this checks the IP(s) resolved *now*. If you don't connect
 * immediately afterward, or your HTTP client re-resolves DNS itself, an
 * attacker controlling DNS could switch the answer between your check and
 * your actual connection (DNS rebinding, TOCTOU). For full protection,
 * resolve once, validate with isPrivateOrReservedIp(), and force your HTTP
 * client to connect to that exact validated IP.
 *
 * @param {string} url
 * @returns {Promise<boolean>}
 */
async function isPublicHttpUrl(url) {
  if (!isValidUrl(url)) return false;
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false;
  }

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    return false;
  }
  if (addresses.length === 0) return false;

  return addresses.every((a) => !isPrivateOrReservedIp(a.address));
}

module.exports = { isPrivateOrReservedIp, isPublicHttpUrl };
