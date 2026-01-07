import nmap
import json

def run_recon(target: str):
    scanner = nmap.PortScanner()

    print(f"[+] Scanning target: {target}")
    scanner.scan(hosts=target, arguments="-sV -Pn")

    result = {
        "target": target,
        "ports": [],
        "services": {}
    }

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]
                result["ports"].append(port)
                result["services"][port] = {
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version")
                }

    return result


def save_result(data, path="facts/scan_result.json"):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
