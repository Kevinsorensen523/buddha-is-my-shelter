"""SSRF-hardening helpers: checking whether an IP or resolved hostname is
safe to let a server-side request reach."""

import ipaddress
import socket

from .validator import is_valid_url
from urllib.parse import urlparse


def is_private_or_reserved_ip(ip: str) -> bool:
    """Reports whether ip is loopback, private-use, link-local, multicast,
    or otherwise non-public. Useful to re-validate an IP your own HTTP
    client resolved right before connecting, as a defense against DNS
    rebinding (see is_public_http_url's caveat)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsable -- treat as unsafe rather than silently allowing it
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def is_public_http_url(url: str) -> bool:
    """Reports whether url is an absolute http(s) URL whose hostname
    resolves (via DNS) to at least one address, all of which are public.

    This performs a real DNS lookup and is therefore not a pure/fast check
    like is_valid_url() -- use that first for cheap structural rejection,
    and this only when about to make a server-side request to a
    caller-supplied URL.

    Caveat: this checks the IP(s) resolved *now*. If you don't connect
    immediately afterward, or your HTTP client re-resolves DNS itself, an
    attacker controlling DNS could switch the answer between your check and
    your actual connection (DNS rebinding, TOCTOU). For full protection,
    resolve once, validate with is_private_or_reserved_ip(), and force your
    HTTP client to connect to that exact validated IP.
    """
    if not is_valid_url(url):
        return False
    host = urlparse(url).hostname
    if not host:
        return False

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False

    for info in infos:
        ip = info[4][0]
        if is_private_or_reserved_ip(ip):
            return False
    return True
