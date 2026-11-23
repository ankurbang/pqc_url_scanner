import streamlit as st
from scanner.url_scanner import scan_url

st.set_page_config(
    page_title="PQC URL Security Scanner",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 PQC URL Security Scanner")
st.caption("Assess the publicly observable TLS endpoint for post-quantum cryptography (PQC) readiness.")

with st.expander("What this scanner checks"):
    st.markdown("""
    - TLS version and negotiated protocol
    - Cipher suite
    - Certificate public-key and signature algorithms
    - Classical vs PQ/hybrid key exchange indicators
    - PQC support observed through controlled TLS probes when OpenSSL supports it
    - A transparent readiness score and remediation guidance

    **Important:** This is an endpoint-level assessment, not proof that an organization is completely
    quantum-safe. Internal PKI, databases, APIs, HSMs, backups, application crypto, and third-party
    systems are outside the scope of a public URL scan.
    """)

url = st.text_input("Enter URL", placeholder="https://example.com")

col1, col2 = st.columns([1, 5])
with col1:
    scan = st.button("🔍 Scan URL", type="primary", use_container_width=True)

if scan:
    if not url.strip():
        st.error("Please enter a URL.")
        st.stop()

    with st.spinner("Scanning TLS endpoint..."):
        result = scan_url(url.strip())

    if result["status"] == "error":
        st.error(result["message"])
        if result.get("details"):
            st.code(result["details"])
        st.stop()

    summary = result["summary"]
    score = summary["score"]

    if score >= 80:
        label, icon = "PQC READY (OBSERVED)", "🟢"
    elif score >= 50:
        label, icon = "PARTIALLY PQC READY", "🟡"
    else:
        label, icon = "NOT PQC READY", "🔴"

    st.subheader(f"{icon} {label}")
    st.progress(score / 100, text=f"PQC readiness score: {score}/100")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Score", f"{score}/100")
    m2.metric("TLS", result["tls"]["version"] or "Unknown")
    m3.metric("Cipher", result["tls"]["cipher"] or "Unknown")
    m4.metric("PQC KEX", "Observed" if result["pqc"]["pqc_kex_observed"] else "Not observed")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("TLS")
        st.write(f"**Host:** `{result['target']['host']}`")
        st.write(f"**Port:** `{result['target']['port']}`")
        st.write(f"**TLS version:** `{result['tls']['version'] or 'Unknown'}`")
        st.write(f"**Cipher:** `{result['tls']['cipher'] or 'Unknown'}`")
        st.write(f"**Negotiated group:** `{result['tls']['group'] or 'Unknown'}`")
        st.write(f"**ALPN:** `{result['tls']['alpn'] or 'Unknown'}`")

    with right:
        st.subheader("Certificate")
        st.write(f"**Public key:** `{result['certificate']['public_key'] or 'Unknown'}`")
        st.write(f"**Signature:** `{result['certificate']['signature'] or 'Unknown'}`")
        st.write(f"**Subject:** `{result['certificate']['subject'] or 'Unknown'}`")
        st.write(f"**Issuer:** `{result['certificate']['issuer'] or 'Unknown'}`")

    st.subheader("PQC Assessment")
    st.write(
        f"**PQC key exchange observed:** "
        f"{'Yes' if result['pqc']['pqc_kex_observed'] else 'No'}"
    )
    if result["pqc"]["probe_notes"]:
        st.info(result["pqc"]["probe_notes"])

    st.subheader("Findings")
    for finding in result["findings"]:
        icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "INFO": "ℹ️"}.get(
            finding["severity"], "•"
        )
        st.write(f"{icon} **{finding['title']}** — {finding['detail']}")

    st.subheader("Recommendations")
    for item in result["recommendations"]:
        st.write(f"- {item}")

    with st.expander("Raw scanner data"):
        st.json(result)
