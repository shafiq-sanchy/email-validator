import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
import socket
from email_validator import validate_email, EmailNotValidError
import io

# ===== Helper functions =====
def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers], key=lambda x: x[0])
        return [host for _, host in mx_records]
    except Exception:
        return []

def smtp_check(mx_host, sender, recipient, timeout=8):
    try:
        srv = smtplib.SMTP(timeout=timeout)
        srv.connect(mx_host)
        srv.helo()
        srv.mail(sender)
        code, message = srv.rcpt(recipient)
        srv.quit()
        return code, message.decode() if isinstance(message, bytes) else str(message)
    except Exception as e:
        return None, f"error: {e}"

def validate_email_entry(email, sender="verify@example.com"):
    result = {
        "email": email,
        "syntax_valid": False,
        "mx_found": False,
        "mx_hosts": "",
        "rcpt_code": "",
        "rcpt_msg": ""
    }
    try:
        v = validate_email(email)
        normalized = v["email"]
        result["syntax_valid"] = True
    except EmailNotValidError as e:
        result["rcpt_msg"] = f"invalid_syntax: {e}"
        return result

    domain = normalized.split('@')[-1]
    mx_hosts = get_mx_records(domain)
    if not mx_hosts:
        result["rcpt_msg"] = "no_mx_found"
        return result

    result["mx_found"] = True
    result["mx_hosts"] = ";".join(mx_hosts)

    # Try first MX host
    code, msg = smtp_check(mx_hosts[0], sender, normalized)
    result["rcpt_code"] = str(code)
    result["rcpt_msg"] = msg
    return result

# ===== Streamlit UI =====
st.title("Free Email Verifier (MX + SMTP Check)")
st.write("Upload a CSV of emails. The app checks syntax, MX, and attempts RCPT.")

uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    if "email" not in df.columns:
        st.error("CSV must have a column named 'email'")
    else:
        results = []
        for email in df["email"].tolist():
            with st.spinner(f"Checking {email}..."):
                results.append(validate_email_entry(email))

        out_df = pd.DataFrame(results)
        st.success("Done! Here are the results:")
        st.dataframe(out_df)

        # Download button
        csv_buffer = io.StringIO()
        out_df.to_csv(csv_buffer, index=False)
        st.download_button(
            "Download Cleaned CSV",
            data=csv_buffer.getvalue(),
            file_name="validated_emails.csv",
            mime="text/csv"
        )
