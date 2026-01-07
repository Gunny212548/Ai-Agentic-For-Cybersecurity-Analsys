# tools/decision.py

def generate_recommendations(risk_report):
    recommendations = []

    findings = sorted(
        risk_report["details"],
        key=lambda x: x.get("cvss") or 0,
        reverse=True
    )

    for f in findings:
        port = f["port"]
        service = f.get("service")
        cvss = f.get("cvss")
        risk = f.get("risk")

        if cvss is None:
            priority = "Monitor"
            impact = "No known CVE detected"
            mitigation = "Continue monitoring and keep service updated"

        elif cvss >= 9.0:
            priority = "IMMEDIATE"
            impact = "Critical vulnerability – remote exploitation likely"
            mitigation = (
                "Immediately patch the service, "
                "restrict network access, "
                "or disable the service if not required"
            )

        elif cvss >= 7.0:
            priority = "HIGH"
            impact = "High risk of compromise"
            mitigation = (
                "Apply security patches, "
                "restrict access, "
                "enable logging and monitoring"
            )

        elif cvss >= 4.0:
            priority = "MEDIUM"
            impact = "Moderate attack surface"
            mitigation = "Harden configuration and monitor activity"

        else:
            priority = "LOW"
            impact = "Low impact vulnerability"
            mitigation = "Monitor and patch during maintenance window"

        recommendations.append({
            "port": port,
            "service": service,
            "cvss": cvss,
            "risk": risk,
            "priority": priority,
            "impact": impact,
            "mitigation": mitigation
        })

    return recommendations
