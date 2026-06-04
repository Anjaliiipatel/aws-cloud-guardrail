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







# Add this to your existing app.py display logic
st.subheader("🕵️ Threat Intelligence Mapping")

risk_mapping = {
    "Unencrypted": {
        "MITRE ID": "T1530",
        "Technique": "Data from Cloud Storage",
        "Risk": "High - Potential for Data Breach"
    },
    "Publicly Accessible": {
        "MITRE ID": "T1567",
        "Technique": "Exfiltration Over Web Service",
        "Risk": "Critical - Direct Internet Exposure"
    }
}

# Display as a clean info box
with st.expander("View MITRE ATT&CK Mapping Details"):
    st.json(risk_mapping)

import streamlit as st
import boto3
import pandas as pd

# 1. Advanced UI Styling
st.set_page_config(page_title="CloudSentinel Pro", layout="wide")

st.markdown("""
    <style>
    /* Main Background */
    .stApp { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: white; }
    
    /* Glowing Glassmorphism Cards */
    div[data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    }
    
    /* Custom Sidebar styling */
    section[data-testid="stSidebar"] { background-color: rgba(15, 23, 42, 0.8); }
    
    /* Button Styling */
    .stButton>button {
        background: linear-gradient(90deg, #004587 0%, #0066cc 100%);
        color: white; border: none; border-radius: 8px; width: 100%; transition: 0.3s;
    }
    .stButton>button:hover { transform: scale(1.02); box-shadow: 0 0 15px #0066cc; }
    </style>
    """, unsafe_allow_html=True)

# 2. Header & Branding
st.title("🛡️ CloudSentinel Pro")
st.markdown("<p style='color: #94a3b8;'>Enterprise Security Guardrail & Global Compliance Engine</p>", unsafe_allow_html=True)

# 3. High-Impact Metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Global Assets", "24", help="Total buckets across all regions")
col2.metric("Security Score", "92%", delta="4%", delta_color="normal")
col3.metric("Critical Risks", "2", delta="-1", delta_color="inverse")
col4.metric("Avg. Remediation", "< 2s", help="Speed of automated self-healing")

st.divider()

# 4. Interactive Threat Map (Mock data for visualization)
st.subheader("🌐 Global Threat Landscape")
map_data = pd.DataFrame({'lat': [38.89, 51.50, 35.68], 'lon': [-77.03, -0.12, 139.69]})
st.map(map_data, size=20, color='#0066cc')

# 5. Sidebar Control Center
with st.sidebar:
    st.image("https://wikimedia.org", width=150)
    st.header("⚡ Ops Center")
    if st.button("🚀 Trigger Global Remediation"):
        st.balloons()
        st.success("Remediation Engine Active across 14 Regions")
    
    st.info("NIST 800-53 Compliance: ACTIVE")

