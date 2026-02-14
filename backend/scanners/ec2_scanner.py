import boto3

SENSITIVE_PORTS = [22, 3389, 3306, 5432, 27017]

def scan_security_groups():
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()

    findings = []

    for sg in response['SecurityGroups']:
        sg_name = sg['GroupName']

        for permission in sg['IpPermissions']:
            from_port = permission.get('FromPort')
            protocol = permission.get('IpProtocol')

            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')

                if cidr == "0.0.0.0/0":

                    risk = "MEDIUM"

                    if from_port in SENSITIVE_PORTS:
                        risk = "HIGH"

                    if from_port is None:
                        risk = "CRITICAL"

                    findings.append({
                        "service": "EC2",
                        "resource": sg_name,
                        "port": from_port,
                        "protocol": protocol,
                        "cidr": cidr,
                        "risk": risk
                    })

    return findings
