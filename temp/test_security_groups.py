import boto3

ec2 = boto3.client('ec2')

response = ec2.describe_security_groups()

print("\n=== Advanced Security Group Risk Analysis ===\n")

SENSITIVE_PORTS = [22, 3389, 3306, 5432, 27017]

for sg in response['SecurityGroups']:
    print(f"Security Group: {sg['GroupName']}")
    risk_detected = False

    for permission in sg['IpPermissions']:
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        protocol = permission.get('IpProtocol')

        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')

            if cidr == "0.0.0.0/0":

                # All ports open
                if from_port is None:
                    print("  [CRITICAL] All ports open to the internet!")
                    risk_detected = True

                # Sensitive ports
                elif from_port in SENSITIVE_PORTS:
                    print(f"  [HIGH RISK] Sensitive port {from_port} exposed to internet!")
                    risk_detected = True

                # Any other open port
                else:
                    print(f"  [MEDIUM RISK] Port {from_port} open to entire internet.")
                    risk_detected = True

    if not risk_detected:
        print("  No internet exposure detected.")

    print("-" * 60)
