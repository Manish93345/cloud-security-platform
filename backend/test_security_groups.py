import boto3

ec2 = boto3.client('ec2')

response = ec2.describe_security_groups()

print("Security Groups:\n")

for sg in response['SecurityGroups']:
    print(f"Security Group: {sg['GroupName']}")
    for permission in sg['IpPermissions']:
        for ip_range in permission.get('IpRanges', []):
            print(f"  Open Port: {permission.get('FromPort')} to {permission.get('ToPort')} | CIDR: {ip_range.get('CidrIp')}")
    print("-" * 40)
