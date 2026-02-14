import json
import os

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
        "summary": summary,
        "findings": findings
    }

    os.makedirs("reports", exist_ok=True)

    with open("reports/security_report.json", "w") as f:
        json.dump(report, f, indent=4)

    return report
