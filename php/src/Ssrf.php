<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * SSRF-hardening helpers: checking whether an IP or resolved hostname is
 * safe to let a server-side request reach.
 */
final class Ssrf
{
    /**
     * Reports whether $ip (a dotted-quad or IPv6 literal) is loopback,
     * private-use, link-local, multicast, or otherwise non-public. Useful
     * to re-validate an IP your own HTTP client resolved right before
     * connecting, as a defense against DNS rebinding (see isPublicHttpUrl's
     * caveat).
     */
    public static function isPrivateOrReservedIp(string $ip): bool
    {
        // FILTER_FLAG_NO_PRIV_RANGE + FILTER_FLAG_NO_RES_RANGE together
        // reject RFC1918/loopback/link-local/reserved ranges for both
        // IPv4 and IPv6 (covers the 169.254.169.254 cloud metadata target).
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * Reports whether $url is an absolute http(s) URL whose hostname
     * resolves (via DNS) to at least one address, all of which are public.
     *
     * This performs a real DNS lookup and is therefore not a pure/fast
     * check like Validator::isValidUrl() -- use that first for cheap
     * structural rejection, and this only when you're about to make a
     * server-side request to a caller-supplied URL.
     *
     * Caveat: this checks the IP(s) resolved *now*. If you don't connect
     * immediately afterward, or your HTTP client re-resolves DNS itself, an
     * attacker controlling DNS could switch the answer between your check
     * and your actual connection (DNS rebinding, TOCTOU). For full
     * protection, resolve once, validate with isPrivateOrReservedIp(), and
     * force your HTTP client to connect to that exact validated IP.
     */
    public static function isPublicHttpUrl(string $url): bool
    {
        if (!Validator::isValidUrl($url)) {
            return false;
        }
        $host = parse_url($url, PHP_URL_HOST);
        if ($host === null || $host === false) {
            return false;
        }

        $ips = gethostbynamel($host);
        if ($ips === false || count($ips) === 0) {
            return false;
        }
        foreach ($ips as $ip) {
            if (self::isPrivateOrReservedIp($ip)) {
                return false;
            }
        }
        return true;
    }
}
