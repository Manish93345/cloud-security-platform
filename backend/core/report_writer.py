import json
import os
from datetime import datetime

def generate_report(findings):

    summary = {
        "total_findings": len(findings),
        "high": 0,
        "medium": 0,
        "critical": 0
    }

    for item in findings:
        risk = item["risk"].lower()
        if risk in summary:
            summary[risk] += 1

    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "findings": findings
    }

    os.makedirs("reports", exist_ok=True)

    filename = datetime.now().strftime("reports/security_report_%Y-%m-%d_%H-%M-%S.json")

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return report
