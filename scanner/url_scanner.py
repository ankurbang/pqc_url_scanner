from urllib.parse import urlparse

from .certificate import parse_certificate
from .scoring import assess
from .tls_scanner import python_tls_probe, run_openssl_probe


def normalize_url(url: str):
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are supported for PQC TLS assessment.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname is missing.")

    port = parsed.port or 443
    return parsed.hostname, port


def scan_url(url: str) -> dict:
    try:
        host, port = normalize_url(url)
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    tls = python_tls_probe(host, port)
    if tls["error"]:
        return {
            "status": "error",
            "message": f"TLS connection failed for {host}:{port}.",
            "details": tls["error"],
        }

    if not tls["certificate"]:
        return {
            "status": "error",
            "message": "The endpoint did not provide a readable TLS certificate.",
        }

    try:
        certificate = parse_certificate(tls["certificate"])
    except Exception as exc:
        return {
            "status": "error",
            "message": "Could not parse the TLS certificate.",
            "details": str(exc),
        }

    openssl = run_openssl_probe(host, port)
    parsed = openssl["parsed"]

    # Prefer the OpenSSL probe for TLS details when available, because it can expose
    # negotiated group information that Python's ssl API may not expose.
    tls_info = {
        "version": parsed.get("version") or tls["version"],
        "cipher": parsed.get("cipher") or tls["cipher"],
        "group": parsed.get("group"),
        "alpn": parsed.get("alpn") or tls["alpn"],
    }

    pqc = {
        "pqc_kex_observed": openssl["pqc_kex_observed"],
        "pqc_group": openssl["pqc_group"],
        "openssl_version": openssl["version"],
        "probe_notes": (
            "OpenSSL was available and a TLS 1.3 probe was performed."
            if openssl["available"]
            else "OpenSSL was not available; PQC hybrid probing was skipped."
        ),
    }

    summary = assess(tls_info, certificate, pqc)

    return {
        "status": "ok",
        "target": {
            "url": url,
            "host": host,
            "port": port,
        },
        "tls": tls_info,
        "certificate": certificate,
        "pqc": pqc,
        "summary": summary,
        "findings": summary["findings"],
        "recommendations": summary["recommendations"],
    }
