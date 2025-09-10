import requests
from datetime import datetime, timedelta
from math import prod

def get_pub_date(cve_id):
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pub_date = data.get("cveMetadata", {}).get("datePublished")
        return pub_date.split("T")[0] if pub_date else None
    except Exception as e:
        print(f"[⚠️] Erreur récupération date publication pour {cve_id} : {e}")
        return None

def get_epss_score(cve_id, date_str):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}&date={date_str}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return float(data["data"][0]["epss"]) if data["data"] else 0.0
    except Exception as e:
        print(f"[ℹ️] Pas de score EPSS pour {cve_id} à {date_str}. On retourne 0.")
        return 0.0

def get_kev_list_until(date_limit):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        kev_data = resp.json()
        date_limit_dt = datetime.strptime(date_limit, "%Y-%m-%d")
        return set(
            entry["cveID"]
            for entry in kev_data.get("vulnerabilities", [])
            if datetime.strptime(entry.get("dateAdded", "2100-01-01"), "%Y-%m-%d") <= date_limit_dt
        )
    except Exception as e:
        print(f"[⚠️] Erreur récupération KEV list : {e}")
        return set()

def is_in_kev(cve_id, kev_set):
    return 1.0 if cve_id in kev_set else 0.0

def get_dates_every_30_days(d0_str, dn_str, step=30):
    d0 = datetime.strptime(d0_str, "%Y-%m-%d")
    dn = datetime.strptime(dn_str, "%Y-%m-%d")
    current = d0
    dates = []
    while current <= dn:
        dates.append(current.strftime("%Y-%m-%d"))
        current += timedelta(days=step)
    return dates

def datediff(d1_str, d2_str):
    d1 = datetime.strptime(d1_str, "%Y-%m-%d")
    d2 = datetime.strptime(d2_str, "%Y-%m-%d")
    return (d2 - d1).days + 1

def winsize(di, dn, w):
    diff = datediff(di, dn)
    return w if diff >= w else diff

def weight(di, dn, w):
    return winsize(di, dn, w) / w

def calculate_lev(cve_id, d0, dn, w=30):
    date_list = get_dates_every_30_days(d0, dn, w)
    terms = []
    for di in date_list:
        epss = get_epss_score(cve_id, di)
        if epss is not None:
            wt = weight(di, dn, w)
            term = 1 - epss * wt
            terms.append(term)
    if not terms:
        return 0.0
    return 1 - prod(terms)

def get_composite_probability(cve_id, dn=None):
    d0 = get_pub_date(cve_id)
    if not dn:
        dn = datetime.today().strftime('%Y-%m-%d')
    if not d0:
        print(f"[❌] Pas de date de publication pour {cve_id}.")
        return 0.0, 0.0, 0.0, 0.0

    epss_score = get_epss_score(cve_id, dn)
    kev_set = get_kev_list_until(dn)
    kev_score = is_in_kev(cve_id, kev_set)
    lev_score = calculate_lev(cve_id, d0, dn)

    scores = [s for s in [epss_score, kev_score, lev_score] if s is not None]
    composite = max(scores) if scores else 0.0

    return composite, epss_score, kev_score, lev_score
