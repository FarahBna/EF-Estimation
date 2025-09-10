import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime
from comp_prob import get_composite_probability, get_pub_date
from BCalc import get_B_from_cve
import requests

# === Fonctions de support ===

def get_dates_every_N_days(d0_str, dn_str, step=90):
    from datetime import datetime, timedelta
    d0 = datetime.strptime(d0_str, "%Y-%m-%d")
    dn = datetime.strptime(dn_str, "%Y-%m-%d")
    current = d0
    dates = set()
    while current <= dn:
        dates.add(current.strftime("%Y-%m-%d"))
        current += timedelta(days=step)
    return dates

def calculate_ef(cve_id, date_str, lambda_val, w_C, w_I, w_A):
    B = get_B_from_cve(cve_id, w_C, w_I, w_A)
    comp_prob, *_ = get_composite_probability(cve_id, date_str)
    if B is None or comp_prob is None:
        return None
    return B * (1 + lambda_val * comp_prob)

def get_kev_added_date(cve_id):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        kev_data = resp.json()
        for entry in kev_data["vulnerabilities"]:
            if entry["cveID"] == cve_id:
                return entry.get("dateAdded")
    except:
        return None

# === Interface Streamlit ===

st.title("📈 Exposure Factor Evolution Over Time")

cve_id = st.text_input("CVE ID", value="CVE-2021-44228")
lambda_val = st.slider("λ (Lambda)", min_value=0.0, max_value=1.0, value=0.3, step=0.01)
w_C = st.slider("w_C", 0.0, 1.0, 1.0, 0.1)
w_I = st.slider("w_I", 0.0, 1.0, 1.0, 0.1)
w_A = st.slider("w_A", 0.0, 1.0, 1.0, 0.1)

if st.button("📊 Generate EF Curve"):
    d0 = get_pub_date(cve_id)
    if not d0:
        st.error("❌ Could not get publication date.")
    else:
        today = datetime.today().strftime("%Y-%m-%d")
        kev_date = get_kev_added_date(cve_id)

        # 🗓️ Dates importantes
        date_set = get_dates_every_N_days(d0, today, step=90)
        date_set.update([d0, today])
        if kev_date:
            date_set.add(kev_date)

        all_dates = sorted(list(date_set))

        ef_data = []
        errors = []
        for date in all_dates:
            try:
                ef = calculate_ef(cve_id, date, lambda_val, w_C, w_I, w_A)
                if ef is not None:
                    label = "regular"
                    if date == d0:
                        label = "publication"
                    elif date == kev_date:
                        label = "kev"
                    elif date == today:
                        label = "today"
                    ef_data.append({
                        "date": date,
                        "EF": ef,
                        "type": label
                    })
            except Exception as e:
                errors.append(f"Erreur lors du calcul EF pour la date {date} : {e}")

        if ef_data:
            df = pd.DataFrame(ef_data)

            y_min = max(0.0, df["EF"].min() - 0.01)
            y_max = df["EF"].max() + 0.01

            base = alt.Chart(df).encode(
                x=alt.X("date:T", title="Date", axis=alt.Axis(format="%Y-%m")),
                y=alt.Y("EF:Q", title="Exposure Factor", scale=alt.Scale(domain=[y_min, y_max])),
                tooltip=["date:T", "EF:Q", "type"]
            )

            line = base.mark_line(point=True)

            highlight_points = base.mark_point(filled=True, size=120).encode(
                color=alt.Color("type:N",
                                scale=alt.Scale(domain=["publication", "kev", "today"],
                                                range=["green", "orange", "red"]),
                                legend=alt.Legend(title="Important Dates"))
            )

            chart = (line + highlight_points).properties(
                title=f"EF over Time for {cve_id}",
                width=750,
                height=400
            )

            st.altair_chart(chart, use_container_width=True)
        else:
            st.warning("Aucune valeur EF calculable pour afficher.")

        # Affiche les erreurs éventuelles
        if errors:
            for err in errors:
                st.warning(err)
