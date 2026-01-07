# tools/risk_scoring.py

def cvss_to_risk_level(cvss):
    if cvss is None:
        return "Low"
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"


def calculate_risk_from_cvss(findings):
    total_score = 0

    for f in findings:
        cves = f.get("cves", [])

        # เอา CVSS ที่สูงที่สุดของ service นั้น
        max_cvss = None
        for cve in cves:
            score = cve.get("cvss")
            if isinstance(score, (int, float)):
                max_cvss = score if max_cvss is None else max(max_cvss, score)

        f["cvss"] = max_cvss
        f["risk"] = cvss_to_risk_level(max_cvss)

        if max_cvss:
            total_score += max_cvss

    # Risk รวมของทั้งระบบ
    if total_score >= 30:
        overall = "Critical"
    elif total_score >= 20:
        overall = "High"
    elif total_score >= 10:
        overall = "Medium"
    else:
        overall = "Low"

    return {
        "total_cvss_score": round(total_score, 2),
        "overall_risk": overall,
        "details": findings
    }
