import os
import requests
import re
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
api_key = os.getenv("NVD_API_KEY")

# CVSS qualitative to numeric mapping
cvss_mappings = {
    '2.0': {'N': 0.0, 'P': 0.275, 'C': 0.66},
    '3.x': {'N': 0.0, 'L': 0.22, 'H': 0.56}
}

def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {'apiKey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"❌ Failed to get CVE: {cve_id} — {response.status_code}")
        return None

    data = response.json()
    try:
        cve_data = data['vulnerabilities'][0]['cve']
        description = cve_data['descriptions'][0]['value']
        metrics = cve_data.get('metrics', {})

        if 'cvssMetricV31' in metrics:
            version = '3.x'
            vector = metrics['cvssMetricV31'][0]['cvssData']['vectorString']
        elif 'cvssMetricV30' in metrics:
            version = '3.x'
            vector = metrics['cvssMetricV30'][0]['cvssData']['vectorString']
        elif 'cvssMetricV2' in metrics:
            version = '2.0'
            vector = metrics['cvssMetricV2'][0]['cvssData']['vectorString']
        else:
            print("❗ No CVSS vector found")
            return None

        # Extract C, I, A from the vector
        c_match = re.search(r'/C:([A-Z])', vector)
        i_match = re.search(r'/I:([A-Z])', vector)
        a_match = re.search(r'/A:([A-Z])', vector)

        c_qual = c_match.group(1) if c_match else None
        i_qual = i_match.group(1) if i_match else None
        a_qual = a_match.group(1) if a_match else None

        mapping = cvss_mappings[version]

        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_version': version,
            'vector_string': vector,
            'C': (c_qual, mapping.get(c_qual)),
            'I': (i_qual, mapping.get(i_qual)),
            'A': (a_qual, mapping.get(a_qual))
        }

    except Exception as e:
        print(f"❌ Parsing error: {e}")
        return None

def calculate_B(C, I, A, w_C=1.0, w_I=1.0, w_A=1.0):
    if None in (C, I, A):
        print("⚠️ Missing value for C, I, or A. Cannot compute B.")
        return None

    numerator = C * w_C + I * w_I + A * w_A
    denominator = w_C + w_I + w_A
    B = numerator / denominator
    return B

# Example usage
if __name__ == "__main__":
    cve_id = "CVE-2020-0601"
    result = get_cve_info(cve_id)

    if result:
        print("\n✅ CVE DETAILS")
        print(f"CVE ID         : {result['cve_id']}")
        print(f"Description    : {result['description']}")
        print(f"CVSS Version   : {result['cvss_version']}")
        print(f"Vector String  : {result['vector_string']}")
        print(f"Confidentiality: {result['C'][0]} → {result['C'][1]}")
        print(f"Integrity      : {result['I'][0]} → {result['I'][1]}")
        print(f"Availability   : {result['A'][0]} → {result['A'][1]}")

        # Extract numeric values
        C_val = result['C'][1]
        I_val = result['I'][1]
        A_val = result['A'][1]

        # You can customize weights here
        w_C = 1
        w_I = 1
        w_A = 1

        B = calculate_B(C_val, I_val, A_val, w_C, w_I, w_A)

        if B is not None:
            print(f"Calculated B   : {B:.4f}")

def get_B_from_cve(cve_id, w_C=1.0, w_I=1.0, w_A=1.0):
    result = get_cve_info(cve_id)
    if result:
        C_val = result['C'][1]
        I_val = result['I'][1]
        A_val = result['A'][1]
        return calculate_B(C_val, I_val, A_val, w_C, w_I, w_A)
    return None
