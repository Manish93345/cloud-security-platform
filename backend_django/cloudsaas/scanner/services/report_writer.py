import os
from datetime import datetime
from django.conf import settings
import json

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

    # Root project folder
    root_dir = settings.BASE_DIR.parent
    reports_dir = os.path.join(root_dir, "reports")

    os.makedirs(reports_dir, exist_ok=True)

    filename = os.path.join(
        reports_dir,
        datetime.now().strftime("security_report_%Y-%m-%d_%H-%M-%S.json")
    )

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return report
