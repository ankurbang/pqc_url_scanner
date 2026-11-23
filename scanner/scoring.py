def assess(tls: dict, certificate: dict, pqc: dict) -> dict:
    score = 0
    findings = []
    recommendations = []

    version = (tls.get("version") or "").upper()
    cipher = (tls.get("cipher") or "").upper()
    group = (tls.get("group") or "").upper()
    public_key = (certificate.get("public_key") or "").upper()
    signature = (certificate.get("signature") or "").upper()

    if version == "TLSV1.3" or version == "TLS 1.3":
        score += 20
        findings.append({
            "severity": "PASS",
            "title": "TLS 1.3",
            "detail": "The endpoint negotiated TLS 1.3."
        })
    elif "TLSV1.2" in version or "TLS 1.2" in version:
        score += 10
        findings.append({
            "severity": "WARN",
            "title": "TLS 1.2",
            "detail": "TLS 1.2 is still widely deployed but is not the preferred baseline for a PQ migration."
        })
        recommendations.append("Prioritize TLS 1.3 for modern cryptographic agility.")
    else:
        findings.append({
            "severity": "FAIL",
            "title": "Unknown/legacy TLS",
            "detail": "The scanner could not confirm a modern TLS version."
        })
        recommendations.append("Investigate and upgrade the public TLS configuration.")

    if pqc.get("pqc_kex_observed"):
        score += 50
        findings.append({
            "severity": "PASS",
            "title": "PQC/hybrid key exchange observed",
            "detail": f"Observed {pqc.get('pqc_group') or 'a PQC-capable group'} during the probe."
        })
    else:
        findings.append({
            "severity": "WARN",
            "title": "No PQC/hybrid key exchange observed",
            "detail": "The probe did not observe a recognized ML-KEM hybrid TLS group."
        })
        recommendations.append(
            "Evaluate enabling a standardized ML-KEM hybrid TLS key-exchange configuration "
            "where your TLS stack, CDN, proxy, and client population support it."
        )

    if public_key.startswith("RSA"):
        score += 5
        findings.append({
            "severity": "WARN",
            "title": "Classical certificate key",
            "detail": f"The certificate uses {certificate.get('public_key')}, which is not a PQ signature scheme."
        })
        recommendations.append("Plan migration of certificate/authentication signatures toward PQ-capable PKI as ecosystem support matures.")
    elif public_key.startswith("EC"):
        score += 5
        findings.append({
            "severity": "WARN",
            "title": "Classical elliptic-curve certificate key",
            "detail": f"The certificate uses {certificate.get('public_key')}, which is not a PQ signature scheme."
        })
        recommendations.append("Track PQ certificate/PKI support and prepare crypto-agility for PQ signatures.")
    elif "ML-DSA" in public_key or "SLH-DSA" in public_key:
        score += 20
        findings.append({
            "severity": "PASS",
            "title": "PQC certificate key",
            "detail": "A recognized PQ signature key was detected."
        })
    else:
        findings.append({
            "severity": "INFO",
            "title": "Certificate key",
            "detail": f"Detected {certificate.get('public_key') or 'unknown'}."
        })

    if "SHA1" in signature or "MD5" in signature:
        findings.append({
            "severity": "FAIL",
            "title": "Weak certificate signature hash",
            "detail": f"Detected {certificate.get('signature')}."
        })
        recommendations.append("Replace certificates using obsolete signature hashes.")
    elif "SHA256" in signature or "SHA384" in signature or "SHA512" in signature:
        score += 5
        findings.append({
            "severity": "PASS",
            "title": "Modern certificate hash",
            "detail": f"Detected {certificate.get('signature')}."
        })

    if "AES_256" in cipher or "CHACHA20" in cipher:
        score += 10
        findings.append({
            "severity": "PASS",
            "title": "Modern symmetric cipher",
            "detail": f"Detected {certificate.get('public_key') and cipher or cipher}."
        })
    elif cipher:
        score += 5
        findings.append({
            "severity": "INFO",
            "title": "Cipher",
            "detail": f"Detected {cipher}."
        })

    score = min(100, score)

    if not recommendations:
        recommendations.append("Maintain crypto-agility and continuously monitor TLS/PQC capabilities.")

    return {
        "score": score,
        "findings": findings,
        "recommendations": recommendations,
    }
