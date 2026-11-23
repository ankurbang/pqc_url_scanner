# PQC URL Security Scanner

A Streamlit application that assesses the publicly observable TLS endpoint of an HTTPS URL for post-quantum cryptography (PQC) readiness.

## Scope

The scanner checks:

- TLS version
- Negotiated cipher
- Negotiated TLS group when OpenSSL exposes it
- Certificate public-key algorithm
- Certificate signature hash
- PQ/hybrid TLS groups such as X25519MLKEM768 when supported by the installed OpenSSL
- Transparent readiness score and recommendations

## Important limitation

This is an **endpoint-level PQC readiness assessment**. It does not prove that an organization is completely quantum-safe.

It cannot inspect:

- internal services
- internal PKI
- databases
- HSMs/KMS
- backups
- source code
- application-level cryptography
- third-party dependencies
- private APIs
- non-public TLS endpoints

## Prerequisites

Python 3.10+ and OpenSSL.

Check:

```bash
python3 --version
openssl version
```

For meaningful PQC hybrid probing, use a recent OpenSSL release with ML-KEM TLS support.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

Then open the local Streamlit URL and enter:

```text
https://example.com
```

You can also enter:

```text
example.com
```

and the app will normalize it to HTTPS.

## Scoring

The score is deliberately an **indicative readiness score**, not a compliance certification.

The largest positive signal is observed PQ/hybrid key exchange. Classical RSA/ECDSA certificates are reported as migration items rather than being treated as proof that the entire endpoint is unsafe.

## Recommended next version

For an enterprise-grade version, add:

- TLS 1.2/1.3 capability matrix
- explicit ML-KEM group negotiation tests
- certificate chain analysis
- OCSP/CRL checks
- DNSSEC
- HSTS
- CT log checks
- HTTP security headers
- CBOM/QBOM export
- JSON/PDF report
- historical scan database
- batch domain scanning
- scheduled monitoring
- CVE/configuration checks
- CDN/load-balancer detection
- crypto-agility maturity scoring
- NIST-aligned migration reporting
