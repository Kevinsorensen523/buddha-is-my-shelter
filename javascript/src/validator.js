'use strict';

/**
 * Input validation and output-encoding helpers.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_CHARS_RE = /[\r\n\t]/;
const allowListCache = new Map();

function isValidEmail(email) {
  if (!email || CONTROL_CHARS_RE.test(email)) return false;
  return EMAIL_RE.test(email);
}

/** Only absolute http(s) URLs are accepted. */
function isValidUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  return (url.protocol === 'http:' || url.protocol === 'https:') && url.hostname !== '';
}

/** @param {string} allowedChars a character-class body, e.g. "a-zA-Z0-9_-" */
function isAllowListed(value, allowedChars) {
  let re = allowListCache.get(allowedChars);
  if (!re) {
    // allowedChars is a caller-supplied character class by design (the
    // allow-list feature's whole purpose); callers must not pass untrusted input here.
    // eslint-disable-next-line security/detect-non-literal-regexp
    re = new RegExp(`^[${allowedChars}]*$`);
    allowListCache.set(allowedChars, re);
  }
  return re.test(value);
}

/**
 * Guards against path traversal. Returns the bare filename when safe;
 * callers must still join it with a trusted, fixed base directory.
 */
function sanitizeFilename(filename) {
  if (!filename || filename.includes('\0') || filename.includes('/') || filename.includes('\\')) {
    throw new RangeError('securekit: invalid filename');
  }
  const trimmed = filename.trim();
  if (trimmed === '' || trimmed === '.' || trimmed === '..') {
    throw new RangeError('securekit: invalid filename');
  }
  return trimmed;
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** HTML-escapes for safe inclusion in HTML body context (prevents XSS). */
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

module.exports = { isValidEmail, isValidUrl, isAllowListed, sanitizeFilename, escapeHtml };
