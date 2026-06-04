import streamlit as st
import boto3
import pandas as pd

# 1. Page Configuration & Styling
st.set_page_config(page_title="CloudSentinel", page_icon="🛡️", layout="wide")

# Custom CSS for a clean, professional look
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ CloudSentinel: Security Guardrail")

# 2. Logic to fetch AWS data
def get_s3_data():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    report = []
    
    for b in buckets:
        name = b['Name']
        # Check Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            enc_status = "Secure"
        except:
            enc_status = "Vulnerable"
            
        # Check Public Access
        try:
            p_block = s3.get_public_access_block(Bucket=name)
            pub_status = "Blocked" if all(p_block['PublicAccessBlockConfiguration'].values()) else "Warning"
        except:
            pub_status = "Open"
            
        report.append({
            "Bucket Name": name, 
            "Encryption": enc_status, 
            "Public Access": pub_status
        })
    return report

# 3. Building the UI
data = get_s3_data()
df = pd.DataFrame(data)

# --- Top Row: Metrics ---
col1, col2, col3 = st.columns(3)
total = len(df)
vulnerable = len(df[df['Encryption'] == 'Vulnerable'])
secure_pct = int(((total - vulnerable) / total) * 100) if total > 0 else 0

with col1:
    st.metric("Total Assets", total)
with col2:
    st.metric("Security Score", f"{secure_pct}%", delta=f"{secure_pct - 100}%", delta_color="inverse")
with col3:
    st.metric("Open Risks", vulnerable, delta_color="normal")

st.divider()

# --- Middle Row: Data Table & Visuals ---
st.subheader("📋 Infrastructure Audit Details")

# Style the dataframe for the UI
def color_status(val):
    if val in ['Vulnerable', 'Open', 'Warning']: return 'color: #d9534f; font-weight: bold'
    if val in ['Secure', 'Blocked']: return 'color: #5cb85c; font-weight: bold'
    return ''

st.dataframe(df.style.applymap(color_status, subset=['Encryption', 'Public Access']), use_container_width=True)

# --- Sidebar Actions ---
with st.sidebar:
    st.header("Control Center")
    if st.button("🔄 Refresh Audit"):
        st.rerun()
    
    st.info("This dashboard uses Boto3 to query real-time IAM and S3 configurations.")
    st.success(f"Connected to: {boto3.client('sts').get_caller_identity()['Account']}")

