import streamlit as st
from datetime import datetime
from BCalc import get_B_from_cve
from comp_prob import get_composite_probability

st.set_page_config(page_title="💥 Multi-CVE Risk Calculator", layout="centered")

def calculate_EF(cve_id, dn=None, lambda_val=0.3, w_C=1.0, w_I=1.0, w_A=1.0):
    B = get_B_from_cve(cve_id, w_C, w_I, w_A)
    comp_prob, epss_score, kev_score, lev_score = get_composite_probability(cve_id, dn)

    if B is None or comp_prob is None:
        return None, B, comp_prob, epss_score, kev_score, lev_score

    EF = B * (1 + lambda_val * comp_prob)
    return EF, B, comp_prob, epss_score, kev_score, lev_score

def calculate_AV(av_c, av_i, av_a):
    return (av_c + av_i + av_a) / 3

# === Interface ===
st.title("💥 Multi-CVE Risk Calculator")

# --- CVE Input ---
st.subheader("🧾 CVE IDs to Evaluate")
num_cves = st.number_input("Number of CVEs", min_value=1, max_value=10, value=3, step=1)
cve_ids = []
for i in range(num_cves):
    cve = st.text_input(f"CVE #{i+1}", key=f"cve_{i}", value=f"CVE-2020-060{i+1}")
    if cve.strip():
        cve_ids.append(cve.strip())

# --- Parameters ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("⚖️ CIA Weights for EF")
    w_C = st.number_input("w_C (Confidentiality)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)
    w_I = st.number_input("w_I (Integrity)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)
    w_A = st.number_input("w_A (Availability)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)

with col2:
    st.subheader("🏷️ Asset Value (AV)")
    av_C = st.selectbox("AV - Confidentiality", [1, 2, 3], index=2, format_func=lambda x: f"{x} ({['Low','Moderate','High'][x-1]})")
    av_I = st.selectbox("AV - Integrity", [1, 2, 3], index=1, format_func=lambda x: f"{x} ({['Low','Moderate','High'][x-1]})")
    av_A = st.selectbox("AV - Availability", [1, 2, 3], index=0, format_func=lambda x: f"{x} ({['Low','Moderate','High'][x-1]})")

# Lambda and ARO
st.subheader("🔁 Other Parameters")
lambda_val = st.slider("λ (for EF)", min_value=0.0, max_value=1.0, value=0.3, step=0.01)
aro = st.number_input("🔄 Annualized Rate of Occurrence (ARO)", min_value=0.0, value=1.0, step=0.1)

# Date
st.subheader("📅 Evaluation Date")
use_today = st.checkbox("Use today's date", value=True)
if use_today:
    dn = datetime.today().strftime("%Y-%m-%d")
else:
    user_date = st.date_input("Select evaluation date (dₙ)")
    dn = user_date.strftime("%Y-%m-%d")

# --- Compute ---
if st.button("🧮 Calculate RISK"):
    st.markdown("---")
    st.subheader("📊 Individual EF Results")

    ef_list = []
    AV = calculate_AV(av_C, av_I, av_A)

    for cve_id in cve_ids:
        EF, B, comp_prob, epss_score, kev_score, lev_score = calculate_EF(cve_id, dn, lambda_val, w_C, w_I, w_A)
        if EF is not None:
            ef_list.append(EF)
            st.markdown(f"**{cve_id}**")
            st.write(f"▪️ B = `{B:.4f}`, Composite Probability = `{comp_prob:.4f}`")
            st.write(f"▪️ EF = `{EF:.4f}`, EPSS = `{epss_score:.4f}`" if epss_score else "EPSS not available")
            st.write(f"▪️ KEV = `{kev_score}`, LEV = `{lev_score:.4f}`" if lev_score else "LEV not available")
            st.markdown("---")
        else:
            st.warning(f"⚠️ Skipping {cve_id} — missing data.")

    if ef_list:
        mean_EF = sum(ef_list) / len(ef_list)
        risk = AV * mean_EF * aro

        st.subheader("📌 Final Risk Assessment")
        st.write(f"**Evaluation Date (dₙ):** `{dn}`")
        st.write(f"**Number of CVEs evaluated:** `{len(ef_list)}`")
        st.write(f"**Average EF:** `{mean_EF:.4f}`")
        st.write(f"**AV (Asset Value):** `{AV:.4f}`")
        st.write(f"**ARO:** `{aro}`")
        st.success(f"💥 **RISK = AV × mean(EF) × ARO = `{risk:.4f}`**")
    else:
        st.error("❌ No EF could be calculated. Please check your CVEs or data availability.")
