import streamlit as st
from datetime import datetime
from BCalc import get_B_from_cve
from comp_prob import get_composite_probability

st.set_page_config(page_title="🔐 Exposure Factor Calculator", layout="centered")

def calculate_EF(cve_id, dn=None, lambda_val=0.3, w_C=1.0, w_I=1.0, w_A=1.0):
    B = get_B_from_cve(cve_id, w_C, w_I, w_A)
    comp_prob, epss_score, kev_score, lev_score = get_composite_probability(cve_id, dn)

    if B is None:
        st.error(f"❌ Could not calculate B for {cve_id}")
        return None, None, None, None, None, None
    if comp_prob is None:
        st.error(f"❌ Could not calculate composite_probability for {cve_id}")
        return None, None, None, None, None, None

    EF = B * (1 + lambda_val * comp_prob)
    return EF, B, comp_prob, epss_score, kev_score, lev_score

# === Streamlit Interface ===
st.title("📊 Exposure Factor Calculator")

# User Inputs
cve_id = st.text_input("🔍 CVE ID", value="CVE-2021-44228")

col1, col2 = st.columns(2)

with col1:
    st.subheader("⚖️ Weights")
    w_C = st.number_input("w_C (Confidentiality)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)
    w_I = st.number_input("w_I (Integrity)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)
    w_A = st.number_input("w_A (Availability)", min_value=0.0, max_value=1.0, value=1.0, step=0.1)


with col2:
    st.subheader("🔁 Lambda (λ)")
    lambda_val = st.slider("λ", min_value=0.0, max_value=1.0, value=0.3, step=0.01)

# Date Selection
st.subheader("🗓️ Evaluation Date")
use_today = st.checkbox("Use today's date", value=True)
if use_today:
    dn = datetime.today().strftime("%Y-%m-%d")
else:
    user_date = st.date_input("Select evaluation date (dₙ)")
    dn = user_date.strftime("%Y-%m-%d")

# Action Button
if st.button("🧮 Calculate EF"):
    EF, B, comp_prob, epss_score, kev_score, lev_score = calculate_EF(cve_id, dn, lambda_val, w_C, w_I, w_A)

    if EF is not None:
        st.markdown("---")
        st.subheader("📌 Results")
        st.write(f"**Evaluation Date (dₙ):** `{dn}`")
        st.write(f"**B** (CIA weighted score): `{B:.4f}`")
        st.write(f"**Composite Probability:** `{comp_prob:.4f}`")

        st.subheader("🔎 Composite Probability Details")
        st.write(f"**EPSS(v, dₙ):** `{epss_score:.4f}`" if epss_score is not None else "EPSS: Not available")
        st.write(f"**KEV(v, dₙ):** `{kev_score}`")
        st.write(f"**LEV(v, d₀, dₙ):** `{lev_score:.4f}`")

        st.success(f"✅ **Exposure Factor (EF):** `{EF:.4f}`")
