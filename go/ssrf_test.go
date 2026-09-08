package securekit

import (
	"net"
	"testing"
)

func TestIsPrivateOrReservedIP(t *testing.T) {
	private := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1"}
	public := []string{"8.8.8.8", "1.1.1.1"}

	for _, s := range private {
		if !IsPrivateOrReservedIP(net.ParseIP(s)) {
			t.Errorf("expected %q to be flagged private/reserved", s)
		}
	}
	for _, s := range public {
		if IsPrivateOrReservedIP(net.ParseIP(s)) {
			t.Errorf("expected %q to be flagged public", s)
		}
	}
}

func TestIsPublicHTTPURLRejectsNonHTTPScheme(t *testing.T) {
	if IsPublicHTTPURL("javascript:alert(1)") {
		t.Fatal("expected non-http(s) scheme to be rejected without any DNS lookup")
	}
}

func TestIsPublicHTTPURLRejectsLocalhost(t *testing.T) {
	if IsPublicHTTPURL("http://localhost/") {
		t.Fatal("expected localhost to resolve to loopback and be rejected")
	}
	if IsPublicHTTPURL("http://127.0.0.1/") {
		t.Fatal("expected raw loopback IP to be rejected")
	}
}
