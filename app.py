import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
import socket
from email_validator import validate_email, EmailNotValidError
import io

# ====== CONFIG ======
EXCLUDED_KEYWORDS = [
    "support@", "account", "filter", "team", "hr", "enquiries", "press@", "job", "career",
    "sales", "inquiry", "yourname", "john", "example", "fraud", "scam", "privacy@",
    "no-reply@", "noreply@", "unsubscribe@"
]

EXCLUDED_DOMAINS_SUBSTR = [
    "sentry", "wixpress", "sentry.wixpress.com", "latofonts", "address", "yourdomain",
    "err.abtm.io", "sentry-next", "wix", "mysite", "yoursite", "amazonaws", "localhost",
    "invalid", "example", "website", "2x.png"
]

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", "email.com", "the.benhawy", ".gif", ".svg", ".domain",
    "example", ".webp", ".ico", ".bmp", ".pdf"
)

# ====== HELPERS ======
def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in answers],
            key=lambda x: x[0]
        )
        return [host for _, host in mx_records]
    except Exception:
        return []

def smtp_check(mx_host, sender, recipient, timeout=8):
    """Try RCPT TO check against mail server"""
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

def is_excluded(email):
    """Check if email contains bad keywords, domain substrings, or extensions"""
    e_lower = email.lower()
    # keyword filter
    if any(k in e_lower for k in EXCLUDED_KEYWORDS):
        return True
    # extension filter
    if e_lower.endswith(SKIP_EXTENSIONS):
        return True
    # domain substr filter
    domain = e_lower.split("@")[-1]
    if any(sub in domain for sub in EXCLUDED_DOMAINS_SUBSTR):
        return True
    return False

def validate_email_entry(email, sender="verify@example.com"):
    result = {
        "email": email,
        "syntax_valid": False,
        "mx_found": False,
        "mx_hosts": "",
        "rcpt_code": "",
        "rcpt_msg": "",
        "excluded": is_excluded(email)
    }

    if result["excluded"]:
        result["rcpt_msg"] = "excluded_by_filter"
        return result

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

    # Try first MX host only
    code, msg = smtp_check(mx_hosts[0], sender, normalized)
    result["rcpt_code"] = str(code)
    result["rcpt_msg"] = msg
    return result

# ====== STREAMLIT UI ======
st.title("Sophisticated Email Verifier (MX + SMTP + Filters)")
st.write("Upload or paste emails. App checks syntax, MX, SMTP, and removes garbage emails.")

mode = st.radio("Choose input method:", ["Paste emails", "Upload CSV"])

emails = []
if mode == "Paste emails":
    pasted = st.text_area("Paste emails (one per line)")
    if pasted:
        emails = [e.strip() for e in pasted.splitlines() if e.strip()]
elif mode == "Upload CSV":
    uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        if "email" not in df.columns:
            st.error("CSV must have a column named 'email'")
        else:
            emails = df["email"].tolist()

if emails:
    results = []
    for email in emails:
        with st.spinner(f"Checking {email}..."):
            results.append(validate_email_entry(email))

    out_df = pd.DataFrame(results)

    # Only keep clean, valid emails
    clean_df = out_df[
        (out_df["syntax_valid"]) &
        (out_df["mx_found"]) &
        (~out_df["excluded"])
    ]

    st.success("Done! Here are the clean results:")
    st.dataframe(clean_df)

    # Download button
    csv_buffer = io.StringIO()
    clean_df.to_csv(csv_buffer, index=False)
    st.download_button(
        "Download Cleaned CSV",
        data=csv_buffer.getvalue(),
        file_name="clean_validated_emails.csv",
        mime="text/csv"
    )
