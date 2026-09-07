package securekit

import (
	"errors"
	"html"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

// ErrInvalidInput is returned by validators when input fails validation.
var ErrInvalidInput = errors.New("securekit: invalid input")

// ValidateEmail reports whether email is a syntactically valid address
// (RFC 5322, via net/mail) and rejects surrounding whitespace/control chars.
func ValidateEmail(email string) bool {
	if email == "" || strings.ContainsAny(email, "\r\n\t") {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	// mail.ParseAddress accepts "Name <addr>"; require the parsed address to
	// equal the raw input so display-name tricks are rejected.
	return addr.Address == email
}

// ValidateURL reports whether rawURL is an absolute http(s) URL. Other
// schemes (javascript:, data:, file:, etc.) are rejected to reduce
// SSRF/XSS-via-redirect risk in typical web use cases.
func ValidateURL(rawURL string) bool {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

var allowListCache = map[string]*regexp.Regexp{}

// ValidateAllowList reports whether s contains only characters present in
// allowedChars (a literal character set, e.g. "a-zA-Z0-9_-").
func ValidateAllowList(s, allowedChars string) bool {
	re, ok := allowListCache[allowedChars]
	if !ok {
		re = regexp.MustCompile(`^[` + allowedChars + `]*$`)
		allowListCache[allowedChars] = re
	}
	return re.MatchString(s)
}

// SanitizeFilename guards against path traversal by stripping directory
// components and rejecting empty/dot-only results. It returns the base
// filename only - callers must still join it with a trusted, fixed base
// directory rather than trusting any caller-supplied prefix.
func SanitizeFilename(filename string) (string, error) {
	if filename == "" {
		return "", ErrInvalidInput
	}
	// Reject NUL and path separators outright rather than silently stripping,
	// since silent stripping can turn "a/../b" into a different plausible name.
	if strings.ContainsAny(filename, "\x00/\\") {
		return "", ErrInvalidInput
	}
	trimmed := strings.TrimSpace(filename)
	if trimmed == "" || trimmed == "." || trimmed == ".." {
		return "", ErrInvalidInput
	}
	return trimmed, nil
}

// EscapeHTML output-encodes s for safe inclusion in HTML body context,
// preventing XSS. Equivalent to PHP's htmlspecialchars(ENT_QUOTES).
func EscapeHTML(s string) string {
	return html.EscapeString(s)
}
