def planner_agent(risk_report):
    actions = []

    if not isinstance(risk_report, list):
        print("[!] Planner received invalid risk_report format")
        return actions

    for item in risk_report:
        if not isinstance(item, dict):
            continue

        risk = item.get("risk")
        port = item.get("port")

        if risk == "CRITICAL":
            actions.append({
                "action": "deep_scan",
                "port": port,
                "reason": "Critical CVSS score"
            })

        elif risk == "HIGH":
            actions.append({
                "action": "version_check",
                "port": port,
                "reason": "High risk service"
            })

    return actions
