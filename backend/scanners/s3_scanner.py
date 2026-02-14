import boto3

def scan_s3_buckets():
    s3 = boto3.client('s3')
    findings = []

    buckets = s3.list_buckets()

    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']

        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)

            config = public_access['PublicAccessBlockConfiguration']

            if not all(config.values()):
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "issue": "Public access block disabled",
                    "risk": "HIGH"
                })

        except Exception:
            # If no public access block found, consider risky
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "issue": "No public access block configuration",
                "risk": "HIGH"
            })

    return findings
