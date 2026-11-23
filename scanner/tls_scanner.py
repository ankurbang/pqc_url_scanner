import re
import socket
import ssl
import subprocess
from typing import Dict, Optional


PQC_GROUPS = {
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519MLKEM1024",
    "X25519MLKEM512",
}

def parse_openssl_text(text: str) -> Dict[str, Optional[str]]:
    data = {
        "version": None,
        "cipher": None,
        "group": None,
        "alpn": None,
    }

    patterns = {
        "version": r"Protocol version:\s*(.+)",
        "cipher": r"Ciphersuite:\s*(.+)",
        "group": r"Peer Temp Key:\s*(.+)",
        "alpn": r"ALPN protocol:\s*(.+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            data[key] = m.group(1).strip()

    return data


def openssl_version() -> str:
    try:
        p = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return (p.stdout or p.stderr).strip()
    except Exception:
        return ""


def run_openssl_probe(host: str, port: int = 443) -> Dict:
    result = {
        "available": False,
        "version": "",
        "raw": "",
        "parsed": parse_openssl_text(""),
        "pqc_kex_observed": False,
        "pqc_group": None,
        "error": None,
    }

    result["version"] = openssl_version()
    if not result["version"]:
        result["error"] = "OpenSSL command was not found."
        return result

    result["available"] = True

    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-tls1_3",
        "-brief",
    ]

    try:
        p = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=12,
        )
        raw = (p.stdout or "") + "\n" + (p.stderr or "")
        result["raw"] = raw
        result["parsed"] = parse_openssl_text(raw)

        group = result["parsed"].get("group") or ""
        for pqc_group in PQC_GROUPS:
            if pqc_group.lower() in group.lower():
                result["pqc_kex_observed"] = True
                result["pqc_group"] = pqc_group
                break

    except subprocess.TimeoutExpired:
        result["error"] = "OpenSSL probe timed out."
    except Exception as exc:
        result["error"] = str(exc)

    return result


def python_tls_probe(host: str, port: int = 443) -> Dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    result = {
        "version": None,
        "cipher": None,
        "group": None,
        "alpn": None,
        "certificate": None,
        "error": None,
    }

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["version"] = ssock.version()
                cipher = ssock.cipher()
                result["cipher"] = cipher[0] if cipher else None
                result["alpn"] = ssock.selected_alpn_protocol()
                result["certificate"] = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        result["error"] = str(exc)

    return result
