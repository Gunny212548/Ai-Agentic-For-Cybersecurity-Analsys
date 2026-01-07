# tools/analyzer.py

def analyze_vulnerabilities(recon_data):
    findings = []

    services = recon_data.get("services", {})

    for port, info in services.items():
        name = info.get("name", "")
        product = info.get("product", "")
        version = info.get("version", "")

        # --- RULE-BASED ANALYSIS ---
        if name == "ssh":
            findings.append({
                "port": port,
                "issue": "SSH exposed",
                "risk": "Medium",
                "detail": f"{product} {version} is accessible from internet"
            })

        if name == "http":
            findings.append({
                "port": port,
                "issue": "Web service detected",
                "risk": "Medium",
                "detail": f"{product} {version} may have known vulnerabilities"
            })

        if name == "snmp":
            findings.append({
                "port": port,
                "issue": "SNMP service exposed",
                "risk": "High",
                "detail": "SNMP is often misconfigured (public/private community)"
            })

        if name in ["microsoft-ds", "netbios-ssn"]:
            findings.append({
                "port": port,
                "issue": "SMB service exposed",
                "risk": "High",
                "detail": "SMB exposure can lead to lateral movement"
            })

        if name == "irc":
            findings.append({
                "port": port,
                "issue": "IRC service exposed",
                "risk": "Medium",
                "detail": "IRC is often abused for C2 communication"
            })

    return findings
