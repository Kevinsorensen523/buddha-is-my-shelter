package io.github.securekit;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * SSRF-hardening helpers: checking whether an IP or resolved hostname is
 * safe to let a server-side request reach.
 */
public final class Ssrf {

    private Ssrf() {
    }

    /**
     * Reports whether address is loopback, site-local (private-use),
     * link-local, multicast, or otherwise non-public. Useful to re-validate
     * an IP your own HTTP client resolved right before connecting, as a
     * defense against DNS rebinding (see {@link #isPublicHttpUrl}'s caveat).
     */
    public static boolean isPrivateOrReservedIp(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isMulticastAddress()
                || address.isAnyLocalAddress();
    }

    /**
     * Reports whether url is an absolute http(s) URL whose hostname
     * resolves (via DNS) to at least one address, all of which are public.
     *
     * <p>This performs a real DNS lookup and is therefore not a pure/fast
     * check like {@link Validator#isValidUrl}. Use that first for cheap
     * structural rejection, and this only when about to make a
     * server-side request to a caller-supplied URL.
     *
     * <p>Caveat: this checks the IP(s) resolved <em>now</em>. If you don't
     * connect immediately afterward, or your HTTP client re-resolves DNS
     * itself, an attacker controlling DNS could switch the answer between
     * your check and your actual connection (DNS rebinding, TOCTOU). For
     * full protection, resolve once, validate with
     * {@link #isPrivateOrReservedIp}, and force your HTTP client to
     * connect to that exact validated IP.
     */
    public static boolean isPublicHttpUrl(String url) {
        if (!Validator.isValidUrl(url)) {
            return false;
        }
        String host;
        try {
            host = new URI(url).getHost();
        } catch (Exception e) {
            return false;
        }
        if (host == null) {
            return false;
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return false;
        }
        if (addresses.length == 0) {
            return false;
        }
        for (InetAddress addr : addresses) {
            if (isPrivateOrReservedIp(addr)) {
                return false;
            }
        }
        return true;
    }
}
