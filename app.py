# app.py
import streamlit as st
import re
import csv
import io
import dns.resolver
import smtplib
import socket
import pandas as pd
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from st_copy_to_clipboard import st_copy_to_clipboard

# ==============================
# CONFIG
# ==============================
st.set_page_config(layout="wide", page_title="Advanced Email Validator")

# More comprehensive exclusion lists
EXCLUDED_KEYWORDS = [
    "support@", "info@", "contact@", "admin@", "sales@", "hello@", "team@", "hr@",
    "jobs@", "careers@", "press@", "media@", "privacy@", "security@", "abuse@",
    "noreply@", "no-reply@", "unsubscribe@", "newsletter@", "feedback@", "test@",
    "demo@", "example@", "dummy@", "john.doe@", "jane.doe@"
]

EXCLUDED_DOMAINS_SUBSTR = [
    "example.com", "test.com", "invalid.com", "localhost", "sentry", "wixpress",
    "amazonaws", "fly.dev", "render.com", "cyclic.sh", "glitch.me", "temp-mail.org",
    "10minutemail.com"
]

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".pdf",
    ".zip", ".tar.gz", ".css", ".js"
)

# Domains to ignore for the "max 2 per domain" rule
PUBLIC_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "protonmail.com", "zoho.com", "yandex.com", "gmx.com"
}

# ==============================
# EMAIL VALIDATION HELPERS
# ==============================

def is_valid_syntax(email):
    """Check for basic email syntax validity."""
    regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(regex, email)

def get_exclusion_reason(email):
    """
    Checks if an email matches exclusion criteria and returns the reason.
    Returns a string reason if excluded, otherwise None.
    """
    email_lower = email.lower()
    for keyword in EXCLUDED_KEYWORDS:
        if keyword in email_lower:
            return f"Flagged by keyword: '{keyword.strip('@')}'"
    domain = email_lower.split('@')[-1]
    for sub in EXCLUDED_DOMAINS_SUBSTR:
        if sub in domain:
            return f"Flagged by domain rule: '{sub}'"
    for ext in SKIP_EXTENSIONS:
        if email_lower.endswith(ext):
            return f"Flagged by file extension: '{ext}'"
    return None

@lru_cache(maxsize=1024)
def has_mx_record(domain):
    """Check for MX records for a domain and cache the result."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return False

def smtp_check(email):
    """Perform SMTP check. Treat timeouts/blocks as inconclusive but likely valid."""
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP(timeout=5) as server:
            server.connect(mx_record)
            server.helo(socket.gethostname())
            server.mail('test@example.com')
            code, _ = server.rcpt(email)
            if code == 250:
                return "Valid"
            elif code in [550, 551, 553, 554]:
                return "Mailbox Not Found"
            else:
                return "Valid (SMTP Check Inconclusive)"
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout):
        return "Valid (SMTP Server Busy)"
    except Exception:
        return "Valid (SMTP Check Failed)"

def validate_email(email):
    """Comprehensive email validation returning a detailed status."""
    email = email.strip()
    if not is_valid_syntax(email):
        return {"email": email, "status": "Invalid Syntax"}
    domain = email.split('@')[-1]
    if not has_mx_record(domain):
        return {"email": email, "status": "No MX Record"}
    smtp_status = smtp_check(email)
    return {"email": email, "status": smtp_status}

def limit_emails_per_domain(emails, max_per_domain=2):
    """Filters a list of emails to ensure no more than max_per_domain from any one domain."""
    domain_counts = defaultdict(int)
    limited_emails = []
    for email in emails:
        domain = email.split('@')[1].lower()
        if domain in PUBLIC_DOMAINS:
            limited_emails.append(email)
            continue
        if domain_counts[domain] < max_per_domain:
            limited_emails.append(email)
            domain_counts[domain] += 1
    return limited_emails

# ==============================
# STREAMLIT UI
# ==============================
st.title("🚀 High-Performance Email Validator")
st.markdown("Paste emails or upload a CSV. The app validates them concurrently, filters them intelligently, and lets you manage the results.")

if 'validation_results' not in st.session_state:
    st.session_state.validation_results = None

col1, col2 = st.columns(2)
with col1:
    emails_text = st.text_area("Paste emails (one per line)", height=300, key="email_input_area")
with col2:
    uploaded_file = st.file_uploader("Or upload a CSV file", type=["csv"], key="file_uploader")

emails_to_validate = []
if emails_text:
    emails_to_validate.extend([e.strip() for e in emails_text.splitlines() if e.strip()])
if uploaded_file:
    try:
        content = uploaded_file.read().decode("utf-8")
        csv_reader = csv.reader(io.StringIO(content))
        for row in csv_reader:
            for item in row:
                found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', item)
                emails_to_validate.extend(email.strip() for email in found_emails)
    except Exception as e:
        st.error(f"❌ Error reading CSV file: {e}")

unique_emails = list(dict.fromkeys(emails_to_validate))

if st.button(f"✅ Validate {len(unique_emails)} Emails", type="primary"):
    if not unique_emails:
        st.warning("⚠️ Please provide emails to validate.")
    else:
        results = []
        progress_bar = st.progress(0, text="Starting validation...")
        total_emails = len(unique_emails)
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_email = {executor.submit(validate_email, email): email for email in unique_emails}
            for i, future in enumerate(as_completed(future_to_email)):
                try:
                    results.append(future.result())
                except Exception as exc:
                    email = future_to_email[future]
                    results.append({"email": email, "status": f"Error: {exc}"})
                progress_bar.progress((i + 1) / total_emails, text=f"Validating email {i+1}/{total_emails}")
        st.session_state.validation_results = results
        st.success("Validation complete!")

if st.session_state.validation_results:
    results = st.session_state.validation_results
    
    technically_valid = [res["email"] for res in results if "Valid" in res["status"]]
    
    initially_excluded_emails = []
    exclusion_reasons = []
    pre_filtered_valid = []

    for email in technically_valid:
        reason = get_exclusion_reason(email)
        if reason:
            initially_excluded_emails.append(email)
            exclusion_reasons.append(reason)
        else:
            pre_filtered_valid.append(email)
            
    st.subheader("Excluded Emails")
    st.write("These emails were flagged by your keywords. Review the reason and select any you wish to include.")
    
    if initially_excluded_emails:
        excluded_df = pd.DataFrame({
            "include": [False] * len(initially_excluded_emails),
            "email": initially_excluded_emails,
            "reason": exclusion_reasons
        })
        edited_excluded_df = st.data_editor(
            excluded_df,
            column_config={"include": st.column_config.CheckboxColumn(required=True)},
            key="excluded_editor",
            hide_index=True,
            use_container_width=True
        )
        emails_to_reinclude = edited_excluded_df[edited_excluded_df["include"]]["email"].tolist()
    else:
        st.info("No emails were flagged by the exclusion rules.")
        emails_to_reinclude = []

    final_valid_list = pre_filtered_valid + emails_to_reinclude
    final_limited_list = limit_emails_per_domain(final_valid_list, max_per_domain=2)
    
    st.subheader("✅ Final Validated & Filtered Emails")
    st.metric("Total Emails Ready for Download/Copy", len(final_limited_list))

    if final_limited_list:
        st.dataframe(pd.DataFrame({"email": final_limited_list}), use_container_width=True, hide_index=True)
        
        col3, col4 = st.columns(2)
        with col3:
            final_emails_str = "\n".join(final_limited_list)
            st_copy_to_clipboard(final_emails_str, "📋 Copy Valid Emails")
        with col4:
            csv_output = io.StringIO()
            csv_writer = csv.writer(csv_output)
            csv_writer.writerow(["email"])
            for email in final_limited_list:
                csv_writer.writerow([email])
            csv_data = csv_output.getvalue()
            st.download_button(
                label="📥 Download as CSV",
                data=csv_data,
                file_name="validated_and_filtered_emails.csv",
                mime="text/csv",
            )
    else:
        st.warning("No valid emails to display after filtering.")

st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; font-size: 0.8em; color: grey;">
        © 2025 Sanchy. All rights reserved.
    </div>
    """,
    unsafe_allow_html=True
)
