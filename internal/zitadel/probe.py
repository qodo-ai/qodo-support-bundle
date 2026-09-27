"""Bounded Platform-to-Zitadel connectivity probe."""

from __future__ import annotations

import json
import os
import signal
import socket
import ssl
import sys

from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 256 * 1024
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"

REASON_AUTH_BACKEND_NOT_OIDC = "auth_backend_not_oidc"
REASON_SETTINGS_UNAVAILABLE = "settings_unavailable"
REASON_INVALID_ISSUER = "invalid_issuer"
REASON_HTTP_CLIENT_UNAVAILABLE = "http_client_unavailable"
REASON_REDIRECT_REJECTED = "redirect_rejected"
REASON_HTTP_ERROR = "http_error"
REASON_UNSUPPORTED_ENCODING = "unsupported_encoding"
REASON_RESPONSE_TOO_LARGE = "response_too_large"
REASON_INVALID_JSON = "invalid_json"
REASON_INVALID_DISCOVERY = "invalid_discovery"
REASON_ISSUER_MISMATCH = "issuer_mismatch"
REASON_JWKS_URI_MISMATCH = "jwks_uri_mismatch"
REASON_INVALID_JWKS = "invalid_jwks"
REASON_TLS_ERROR = "tls_error"
REASON_DNS_ERROR = "dns_error"
REASON_CONNECTION_REFUSED = "connection_refused"
REASON_PROXY_ERROR = "proxy_error"
REASON_TIMEOUT = "timeout"
REASON_CONNECTION_ERROR = "connection_error"


def check_result(name, reason="", **fields):
    return {
        "name": name,
        "status": STATUS_FAILED if reason else STATUS_PASSED,
        "reason": reason,
        **fields,
    }


def configuration_failure(reason):
    return {"schema_version": 1, "checks": [check_result("configuration", reason)]}


def validate_issuer(issuer):
    if not isinstance(issuer, str) or not issuer or len(issuer) > 2048:
        raise ValueError(REASON_INVALID_ISSUER)
    parsed = urlsplit(issuer)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(REASON_INVALID_ISSUER)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in issuer
        or "#" in issuer
        or "\\" in issuer
        or any(character.isspace() or ord(character) < 32 for character in issuer)
        or port == 0
    ):
        raise ValueError(REASON_INVALID_ISSUER)
    return issuer


def transport_reason(error):
    import httpx

    chain = []
    current = error
    while current is not None and len(chain) < 12 and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    for error_type, reason in (
        (ssl.SSLError, REASON_TLS_ERROR),
        (socket.gaierror, REASON_DNS_ERROR),
        (ConnectionRefusedError, REASON_CONNECTION_REFUSED),
        (httpx.ProxyError, REASON_PROXY_ERROR),
        (httpx.TimeoutException, REASON_TIMEOUT),
    ):
        if any(isinstance(item, error_type) for item in chain):
            return reason
    return REASON_CONNECTION_ERROR


def read_json(url, timeout):
    import httpx

    try:
        # One client per request prevents response cookies from reaching the next endpoint.
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            with client.stream(
                "GET", url, headers={"Accept-Encoding": "identity"}
            ) as response:
                status = response.status_code
                if status != 200:
                    reason = (
                        REASON_REDIRECT_REJECTED
                        if 300 <= status < 400
                        else REASON_HTTP_ERROR
                    )
                    return None, reason, status
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    return None, REASON_UNSUPPORTED_ENCODING, status
                body = bytearray()
                for chunk in response.iter_raw():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        return None, REASON_RESPONSE_TOO_LARGE, status
                    body.extend(chunk)
                try:
                    return json.loads(body), "", status
                except (ValueError, RecursionError):
                    return None, REASON_INVALID_JSON, status
    except httpx.HTTPError as error:
        return None, transport_reason(error), None


def public_key_shape(key):
    if not isinstance(key, dict):
        return False
    fields = {
        "RSA": ("n", "e"),
        "EC": ("crv", "x", "y"),
        "OKP": ("crv", "x"),
    }.get(key.get("kty") if isinstance(key.get("kty"), str) else "")
    return bool(fields) and all(
        isinstance(key.get(field), str) and bool(key[field]) for field in fields or ()
    )


def probe(issuer, timeout):
    checks = []
    base = issuer.rstrip("/")
    request_timeout = min(5.0, timeout / 3)
    discovery, reason, status = read_json(
        base + "/.well-known/openid-configuration", request_timeout
    )
    if not reason:
        if not isinstance(discovery, dict):
            reason = REASON_INVALID_DISCOVERY
        elif discovery.get("issuer") != issuer:
            reason = REASON_ISSUER_MISMATCH
        elif discovery.get("jwks_uri") != base + "/oauth/v2/keys":
            reason = REASON_JWKS_URI_MISMATCH
    checks.append(check_result("discovery", reason, http_status=status))

    keys, reason, status = read_json(base + "/oauth/v2/keys", request_timeout)
    if not reason and (
        not isinstance(keys, dict)
        or not isinstance(keys.get("keys"), list)
        or not keys["keys"]
        or not all(public_key_shape(key) for key in keys["keys"])
    ):
        reason = REASON_INVALID_JWKS
    checks.append(check_result("jwks", reason, http_status=status))
    return {"schema_version": 1, "issuer": issuer, "checks": checks}


def configured_probe(timeout):
    try:
        from common.config.simple_settings import simple_settings

        if simple_settings.get("auth.client_type") not in ("zitadel", "oidc"):
            return configuration_failure(REASON_AUTH_BACKEND_NOT_OIDC)
        issuer = simple_settings.get("auth.zitadel_issuer")
    except (ImportError, OSError, ValueError, TypeError, AttributeError, RuntimeError):
        return configuration_failure(REASON_SETTINGS_UNAVAILABLE)
    try:
        issuer = validate_issuer(issuer)
    except ValueError:
        return configuration_failure(REASON_INVALID_ISSUER)
    try:
        return probe(issuer, timeout)
    except (ImportError, OSError, ValueError):
        return configuration_failure(REASON_HTTP_CLIENT_UNAVAILABLE)


def main():
    # Imports and settings may log secrets. Preserve only a duplicate of stdout for
    # this bounded report, then discard all imported stdout and stderr.
    with os.fdopen(os.dup(sys.stdout.fileno()), "w") as report_stream:
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
            os.dup2(sink.fileno(), sys.stderr.fileno())
        timeout = float(sys.argv[1])
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        report_stream.write(json.dumps(configured_probe(timeout), separators=(",", ":")) + "\n")
        report_stream.flush()


if __name__ == "__main__":
    main()
