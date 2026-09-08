package securekit

import (
	"net"
	"net/url"
)

// IsPrivateOrReservedIP reports whether ip is a loopback, private-use,
// link-local, multicast, or otherwise non-public address. Useful to
// re-validate an IP your own HTTP client resolved right before connecting,
// as a defense against DNS rebinding (see IsPublicHTTPURL's caveat below).
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// IsPublicHTTPURL reports whether rawURL is an absolute http(s) URL whose
// hostname resolves (via DNS) to at least one address, all of which are
// public (not private/loopback/link-local/reserved -- this specifically
// blocks the common SSRF target of cloud metadata endpoints such as
// 169.254.169.254, which falls under link-local).
//
// This performs a real DNS lookup and is therefore not a pure/fast check
// like ValidateURL -- use ValidateURL first for cheap structural rejection,
// and this only when you're about to make a server-side request to a
// caller-supplied URL.
//
// Caveat: this checks the IP(s) resolved *now*. If you don't connect
// immediately afterward, or your HTTP client re-resolves DNS itself, an
// attacker controlling DNS could switch the answer between your check and
// your actual connection (DNS rebinding, TOCTOU). For full protection,
// resolve once, validate with IsPrivateOrReservedIP, and force your HTTP
// client to connect to that exact validated IP.
func IsPublicHTTPURL(rawURL string) bool {
	if !ValidateURL(rawURL) {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if IsPrivateOrReservedIP(ip) {
			return false
		}
	}
	return true
}
