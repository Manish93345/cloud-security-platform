import boto3

ec2 = boto3.client('ec2')

response = ec2.describe_security_groups()

print("\n=== Security Group Risk Analysis ===\n")

for sg in response['SecurityGroups']:
    print(f"Security Group: {sg['GroupName']}")
    risky_found = False

    for permission in sg['IpPermissions']:
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')

        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')

            # HIGH RISK CONDITION
            if cidr == "0.0.0.0/0" and from_port == 22:
                print("  [HIGH RISK] SSH (Port 22) exposed to entire internet!")
                risky_found = True

    if not risky_found:
        print("  No critical risks detected.")

    print("-" * 50)
