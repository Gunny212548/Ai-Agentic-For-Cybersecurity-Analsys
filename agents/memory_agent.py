import json
from datetime import datetime

def save_scan(target, data):
    record = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data
    }

    with open("memory/scan_history.json", "a") as f:
        f.write(json.dumps(record) + "\n")