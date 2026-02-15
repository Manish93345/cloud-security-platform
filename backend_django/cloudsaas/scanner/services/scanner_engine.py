from .ec2_scanner import scan_security_groups
from .s3_scanner import scan_s3_buckets
from .report_writer import generate_report

def run_full_scan():
    findings = []

    ec2_findings = scan_security_groups()
    findings.extend(ec2_findings)

    s3_findings = scan_s3_buckets()
    findings.extend(s3_findings)

    report = generate_report(findings)
    return report
