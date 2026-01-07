from tools.recon import run_recon
from tools.analyzer import analyze_vulnerabilities
from tools.cve_mapper import map_cves
from tools.risk_scoring import calculate_risk_from_cvss
from agents.llm_analyst import llm_analyst_agent
from agents.planner_agent import planner_agent


def main():
    target = input("Enter target (IP or domain): ")

    # 1️⃣ Recon Agent
    recon_data = run_recon(target)
    print("[✓] Recon completed")

    # 2️⃣ Vulnerability Analyzer Agent
    findings = analyze_vulnerabilities(recon_data)
    print("[✓] Vulnerability Analysis completed")

    # 3️⃣ CVE Mapper Agent
    findings = map_cves(findings)
    print("[✓] CVE Mapping completed")

    # 4️⃣ Risk Scoring Agent (CVSS-based, factual)
    risk_report = calculate_risk_from_cvss(findings)
    print("[✓] CVSS-based Risk Scoring completed")

    # 5️⃣ LLM Analyst Agent (อ่าน + วิเคราะห์เชิงเหตุผล)
    analysis = llm_analyst_agent(recon_data, risk_report)

    print("\n==== LLM Analyst Report ====\n")
    print(analysis)

    # 6️⃣ Planner Agent (ตัดสินใจจากข้อมูลจริง 100%)
    actions = planner_agent(risk_report)

    print("\n==== Planner Actions ====")
    if actions:
        for act in actions:
            print(
                f"- Action: {act['action']} | Port: {act['port']} | Reason: {act['reason']}"
            )
    else:
        print("No actions required")

    # 7️⃣ Feedback Loop (Agent Trigger)
    if actions:
        print("\n[!] Triggering additional scans...")

        for act in actions:
            if act["action"] == "deep_scan":
                print(f"[*] (TODO) Deep scanning port {act['port']}")

            elif act["action"] == "version_check":
                print(f"[*] (TODO) Checking service version on port {act['port']}")

    else:
        print("\n[✓] System stable. No further action required.")


if __name__ == "__main__":
    main()
