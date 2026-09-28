from ollamagate.server.netutil import parse_networks, resolve_client_ip

TRUSTED = parse_networks(["10.0.0.0/8", "127.0.0.1/32"])


def test_untrusted_peer_headers_ignored():
    assert resolve_client_ip("8.8.8.8", {"x-forwarded-for": "1.1.1.1"}, TRUSTED, "direct") == "8.8.8.8"
    assert resolve_client_ip("8.8.8.8", {"cf-connecting-ip": "1.1.1.1"}, TRUSTED, "cloudflare") == "8.8.8.8"


def test_no_trusted_proxies_means_peer():
    assert resolve_client_ip("127.0.0.1", {"x-forwarded-for": "1.1.1.1"}, [], "direct") == "127.0.0.1"


def test_xff_rightmost_untrusted_hop():
    # Client tried to spoof 6.6.6.6 by prepending it.
    headers = {"x-forwarded-for": "6.6.6.6, 203.0.113.9, 10.1.1.1"}
    assert resolve_client_ip("10.0.0.2", headers, TRUSTED, "direct") == "203.0.113.9"


def test_cloudflare_header_from_trusted_peer():
    assert resolve_client_ip("127.0.0.1", {"cf-connecting-ip": "203.0.113.5"}, TRUSTED, "cloudflare") == "203.0.113.5"
    assert resolve_client_ip("127.0.0.1", {"cf-connecting-ip": "garbage"}, TRUSTED, "cloudflare") == "127.0.0.1"
