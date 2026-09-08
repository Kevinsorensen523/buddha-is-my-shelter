package io.github.securekit;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsrfTest {

    @Test
    void isPrivateOrReservedIpFlagsPrivateAddresses() throws UnknownHostException {
        for (String ip : new String[] {"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1"}) {
            assertTrue(Ssrf.isPrivateOrReservedIp(InetAddress.getByName(ip)), ip + " should be flagged");
        }
    }

    @Test
    void isPrivateOrReservedIpAllowsPublicAddresses() throws UnknownHostException {
        for (String ip : new String[] {"8.8.8.8", "1.1.1.1"}) {
            assertFalse(Ssrf.isPrivateOrReservedIp(InetAddress.getByName(ip)), ip + " should be public");
        }
    }

    @Test
    void isPublicHttpUrlRejectsNonHttpScheme() {
        assertFalse(Ssrf.isPublicHttpUrl("javascript:alert(1)"));
    }

    @Test
    void isPublicHttpUrlRejectsLocalhost() {
        assertFalse(Ssrf.isPublicHttpUrl("http://localhost/"));
        assertFalse(Ssrf.isPublicHttpUrl("http://127.0.0.1/"));
    }
}
