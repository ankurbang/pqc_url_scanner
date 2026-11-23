from cryptography import x509
from cryptography.hazmat.primitives import hashes


def _key_description(cert):
    key = cert.public_key()
    name = key.__class__.__name__

    if name == "RSAPublicKey":
        return f"RSA {key.key_size}"
    if name == "ECPublicKey":
        return f"EC ({key.curve.name})"
    if name == "Ed25519PublicKey":
        return "Ed25519"
    if name == "Ed448PublicKey":
        return "Ed448"
    if name == "DHPublicKey":
        return f"DH {key.key_size}"

    return name


def parse_certificate(der_bytes: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der_bytes)

    try:
        sig = cert.signature_hash_algorithm.name
    except Exception:
        sig = "Unknown"

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "public_key": _key_description(cert),
        "signature": sig,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
    }
