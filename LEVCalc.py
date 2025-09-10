import streamlit as st
from datetime import datetime, timedelta
import requests
from math import prod

# ===== Utility functions =====

def get_cve_pub_date_circl(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        metadata = data.get("cveMetadata", {})
        pub_date = metadata.get("datePublished")
        if pub_date:
            try:
                return datetime.fromisoformat(pub_date).strftime('%Y-%m-%d')
            except ValueError:
                return pub_date
    return None

def get_dates_every_30_days(d0_str, dn_str, step=30):
    d0 = datetime.strptime(d0_str, "%Y-%m-%d")
    dn = datetime.strptime(dn_str, "%Y-%m-%d")
    dates = []
    current = d0
    while current <= dn:
        dates.append(current.strftime("%Y-%m-%d"))
        current += timedelta(days=step)
    return dates

def get_epss_score(cve_id, date_str):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}&date={date_str}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if "data" in data and len(data["data"]) > 0:
            return float(data["data"][0]["epss"])
        else:
            return None
    except:
        return None

def datediff(d1_str, d2_str):
    d1 = datetime.strptime(d1_str, "%Y-%m-%d")
    d2 = datetime.strptime(d2_str, "%Y-%m-%d")
    return (d2 - d1).days + 1

def winsize(di_str, dn_str, w):
    diff = datediff(di_str, dn_str)
    return w if diff >= w else diff

def weight(di_str, dn_str, w):
    return winsize(di_str, dn_str, w) / w

# ===== LEV Calculation and Display =====

def calculate_lev_display(cve_id, d0, dn, w=30):
    date_list = get_dates_every_30_days(d0, dn, w)
    epss_scores = []
    terms = []

    for di in date_list:
        epss = get_epss_score(cve_id, di)
        if epss is not None:
            wt = weight(di, dn, w)
            term = 1 - epss * wt
            terms.append(term)
            epss_scores.append((di, epss))

    if not terms:
        st.warning("⚠️ No EPSS data available.")
        return

    product = prod(terms)
    lev = 1 - product
    peak_date, peak_score = max(epss_scores, key=lambda x: x[1])

    st.subheader(f"{cve_id}, published {d0}")
    st.write(f"🔐 **LEV probability:** `{lev:.2f}`")
    st.write(f"📈 **Peak EPSS:** `{peak_score:.2f}` on `{peak_date}`")

    st.markdown("#### EPSS scores:")
    scores_line = " ".join([f"{score:.2f}" for _, score in epss_scores])
    st.code(scores_line)

    st.markdown("#### EPSS dates:")
    dates_line = " ".join([date for date, _ in epss_scores])
    st.code(dates_line)

    st.info(f"Note: final EPSS score adjusted for window size of {len(epss_scores)}")

# ===== Streamlit App =====

st.set_page_config(page_title="LEV Calculator", layout="centered")
st.title("🔐 LEV Score Calculator using EPSS")

cve_input = st.text_input("Enter CVE ID (e.g., CVE-2023-1730)")

dn_choice = st.radio("Select `dn` date option:", ["Use current date", "Enter custom date manually"])

if dn_choice == "Enter custom date manually":
    custom_dn = st.date_input("Choose custom `dn` date", value=datetime.today())
    dn = custom_dn.strftime('%Y-%m-%d')
else:
    dn = datetime.today().strftime('%Y-%m-%d')

if st.button("Calculate LEV Score"):
    if not cve_input:
        st.error("❌ Please enter a valid CVE ID.")
    else:
        d0 = get_cve_pub_date_circl(cve_input)
        if d0:
            calculate_lev_display(cve_input, d0, dn)
        else:
            st.error("❌ Failed to retrieve CVE publication date.")
