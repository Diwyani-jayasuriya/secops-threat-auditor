from auditor import check_security_headers, check_ssl_certificate
import streamlit as st

st.set_page_config(
    page_title="SecOps Threat Auditor", page_icon="🛡️", layout="wide"
)

st.title("🛡️ SecOps Web Exposure & Threat Auditor")
st.markdown(
    "Automated security posture checker for web servers and domain configurations."
)
st.divider()

target = st.text_input(
    "Enter Target Domain / URL:", placeholder="example.com or https://example.com"
)

if st.button("Run Security Audit", type="primary") and target:
    with st.spinner("Analyzing target security configuration..."):
        headers_res = check_security_headers(target)
        ssl_res = check_ssl_certificate(target)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🌐 Security Headers Posture")
        if "error" in headers_res:
            st.error(headers_res["error"])
        else:
            st.metric(
                label="Security Grade",
                value=headers_res["grade"],
                delta=f"Score: {headers_res['score']}/100",
            )

            st.write("#### Detected Headers:")
            if headers_res["headers_found"]:
                for h in headers_res["headers_found"]:
                    st.success(f"✔️ **{h}** is present")
            else:
                st.info("No primary security headers detected.")

            st.write("#### Missing Protections:")
            if headers_res["missing_headers"]:
                for h, desc in headers_res["missing_headers"].items():
                    st.warning(f"⚠️ **{h}**: {desc}")
            else:
                st.success("All recommended security headers are configured!")

    with col2:
        st.subheader("🔒 SSL/TLS Health")
        if "error" in ssl_res:
            st.error(ssl_res["error"])
        else:
            days = ssl_res["days_remaining"]
            st.metric(label="Days to Expiry", value=f"{days} Days")
            st.write(f"**Expiration Date:** `{ssl_res['expires_on']}`")

            if ssl_res["is_valid"]:
                st.success("✔️ Certificate is valid and active.")
            else:
                st.error("❌ Certificate has expired!")