# tools/cve_mapper.py

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves(service, version, limit=3):
    if not service or service == "unknown":
        return []

    query = f"{service} {version}".strip()

    params = {
        "keywordSearch": query,
        "resultsPerPage": limit
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")

            description = cve_data.get("descriptions", [{}])[0].get("value", "")

            metrics = cve_data.get("metrics", {})
            cvss = None
            severity = None

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "cvss": cvss,
                "severity": severity
            })

        return cves

    except Exception as e:
        return [{"error": str(e)}]


def map_cves(findings):
    for f in findings:
        service = f.get("service")
        version = f.get("version")

        f["cves"] = fetch_cves(service, version)

    return findings
