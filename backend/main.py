from scanners.ec2_scanner import scan_security_groups
from scanners.s3_scanner import scan_s3_buckets
from core.report_writer import generate_report

def run_full_scan():
    findings = []

    # EC2 Scan
    ec2_findings = scan_security_groups()
    findings.extend(ec2_findings)

    # S3 Scan
    s3_findings = scan_s3_buckets()
    findings.extend(s3_findings)

    return findings


if __name__ == "__main__":
    results = run_full_scan()

    report = generate_report(results)

    print("\n=== Security Report Summary ===\n")
    print(report["summary"])
