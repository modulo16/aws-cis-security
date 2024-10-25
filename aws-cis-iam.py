import boto3
import json
from datetime import datetime, timezone

def check_iam_policies():
    """Check IAM-related CIS controls"""
    iam = boto3.client('iam')
    findings = []
    
    # 1.1 Check root account MFA
    try:
        account_summary = iam.get_account_summary()
        if not account_summary['SummaryMap']['AccountMFAEnabled']:
            findings.append({
                'Control': '1.1',
                'Finding': 'Root account MFA is not enabled',
                'Severity': 'CRITICAL'
            })
    except Exception as e:
        findings.append({
            'Control': '1.1',
            'Finding': f'Error checking root MFA: {str(e)}',
            'Severity': 'ERROR'
        })

    # 1.2 Check IAM users
    try:
        users = iam.list_users()['Users']
        for user in users:
            # Check access keys age
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in access_keys:
                key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                if key_age > 90:
                    findings.append({
                        'Control': '1.2',
                        'Finding': f"Access key for user {user['UserName']} is {key_age} days old",
                        'Severity': 'HIGH'
                    })
            
            # Check MFA status
            try:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if not mfa_devices:
                    findings.append({
                        'Control': '1.2',
                        'Finding': f"User {user['UserName']} does not have MFA enabled",
                        'Severity': 'HIGH'
                    })
            except Exception as e:
                findings.append({
                    'Control': '1.2',
                    'Finding': f"Error checking MFA for user {user['UserName']}: {str(e)}",
                    'Severity': 'ERROR'
                })
    except Exception as e:
        findings.append({
            'Control': '1.2',
            'Finding': f'Error checking IAM users: {str(e)}',
            'Severity': 'ERROR'
        })

    # 1.3 Check credential usage
    try:
        credential_report = iam.get_credential_report()
        report_csv = credential_report['Content'].decode('utf-8')
        for line in report_csv.splitlines()[1:]:  # Skip header
            fields = line.split(',')
            username = fields[0]
            password_enabled = fields[3]
            password_last_used = fields[4]
            if password_enabled == 'true' and password_last_used != 'N/A':
                last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                days_since_use = (datetime.now(timezone.utc) - last_used).days
                if days_since_use > 90:
                    findings.append({
                        'Control': '1.3',
                        'Finding': f"User {username} has not used console password in {days_since_use} days",
                        'Severity': 'MEDIUM'
                    })
    except Exception as e:
        findings.append({
            'Control': '1.3',
            'Finding': f'Error checking credential usage: {str(e)}',
            'Severity': 'ERROR'
        })

    return findings

def main():
    findings = check_iam_policies()
    print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()
