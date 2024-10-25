import boto3
import json

def check_networking_configuration():
    """Check networking-related CIS controls"""
    findings = []
    
    ec2 = boto3.client('ec2')
    
    # Check Security Groups
    try:
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            # Check for overly permissive inbound rules
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                            findings.append({
                                'Control': '4.1',
                                'Finding': f"Security Group {sg['GroupId']} allows unrestricted SSH access",
                                'Severity': 'CRITICAL'
                            })
                        if rule.get('FromPort') == 3389 or rule.get('ToPort') == 3389:
                            findings.append({
                                'Control': '4.2',
                                'Finding': f"Security Group {sg['GroupId']} allows unrestricted RDP access",
                                'Severity': 'CRITICAL'
                            })
    except Exception as e:
        findings.append({
            'Control': '4.1',
            'Finding': f'Error checking security groups: {str(e)}',
            'Severity': 'ERROR'
        })
    
    # Check Network ACLs
    try:
        nacls = ec2.describe_network_acls()['NetworkAcls']
        for nacl in nacls:
            for entry in nacl['Entries']:
                if entry['CidrBlock'] == '0.0.0.0/0' and entry['RuleAction'] == 'allow':
                    findings.append({
                        'Control': '4.3',
                        'Finding': f"Network ACL {nacl['NetworkAclId']} has overly permissive rules",
                        'Severity': 'HIGH'
                    })
    except Exception as e:
        findings.append({
            'Control': '4.3',
            'Finding': f'Error checking network ACLs: {str(e)}',
            'Severity': 'ERROR'
        })
    
    # Check VPC Flow Logs
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        flow_log_vpc_ids = {log['ResourceId'] for log in flow_logs}
        
        for vpc in vpcs:
            if vpc['VpcId'] not in flow_log_vpc_ids:
                findings.append({
                    'Control': '4.4',
                    'Finding': f"VPC {vpc['VpcId']} does not have flow logs enabled",
                    'Severity': 'MEDIUM'
                })
    except Exception as e:
        findings.append({
            'Control': '4.4',
            'Finding': f'Error checking VPC flow logs: {str(e)}',
            'Severity': 'ERROR'
        })

    return findings

def main():
    findings = check_networking_configuration()
    print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()
