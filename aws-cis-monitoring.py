import boto3
import json

def check_monitoring_configuration():
    """Check monitoring-related CIS controls"""
    findings = []
    
    cloudwatch = boto3.client('cloudwatch')
    sns = boto3.client('sns')
    
    # Check CloudWatch Alarms
    try:
        # Check for unauthorized API calls alarm
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
        required_alarms = {
            'UnauthorizedAPICalls': False,
            'NoMFAConsoleSignin': False,
            'RootAccountUsage': False,
            'IAMPolicyChanges': False,
            'CloudTrailConfigChanges': False,
            'ConsoleAuthFailures': False,
            'CMKDisableDelete': False
        }
        
        for alarm in alarms:
            alarm_name = alarm['AlarmName'].lower()
            
            if 'unauthorized' in alarm_name and 'api' in alarm_name:
                required_alarms['UnauthorizedAPICalls'] = True
            elif 'mfa' in alarm_name and 'console' in alarm_name:
                required_alarms['NoMFAConsoleSignin'] = True
            elif 'root' in alarm_name and 'account' in alarm_name:
                required_alarms['RootAccountUsage'] = True
            elif 'iam' in alarm_name and 'policy' in alarm_name:
                required_alarms['IAMPolicyChanges'] = True
            elif 'cloudtrail' in alarm_name and 'config' in alarm_name:
                required_alarms['CloudTrailConfigChanges'] = True
            elif 'console' in alarm_name and 'fail' in alarm_name:
                required_alarms['ConsoleAuthFailures'] = True
            elif 'kms' in alarm_name and ('disable' in alarm_name or 'delete' in alarm_name):
                required_alarms['CMKDisableDelete'] = True
        
        for alarm_type, exists in required_alarms.items():
            if not exists:
                findings.append({
                    'Control': '3.1',
                    'Finding': f"Missing CloudWatch alarm for {alarm_type}",
                    'Severity': 'HIGH'
                })
    except Exception as e:
        findings.append({
            'Control': '3.1',
            'Finding': f'Error checking CloudWatch alarms: {str(e)}',
            'Severity': 'ERROR'
        })
    
    # Check SNS Topics for Alarm Actions
    try:
        topics = sns.list_topics()['Topics']
        if not topics:
            findings.append({
                'Control': '3.2',
                'Finding': 'No SNS topics found for alarm notifications',
                'Severity': 'MEDIUM'
            })
        else:
            for topic in topics:
                try:
                    subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])['Subscriptions']
                    if not subscriptions:
                        findings.append({
                            'Control': '3.2',
                            'Finding': f"SNS topic {topic['TopicArn']} has no subscriptions",
                            'Severity': 'MEDIUM'
                        })
                except Exception as e:
                    findings.append({
                        'Control': '3.2',
                        'Finding': f"Error checking subscriptions for topic {topic['TopicArn']}: {str(e)}",
                        'Severity': 'ERROR'
                    })
    except Exception as e:
        findings.append({
            'Control': '3.2',
            'Finding': f'Error checking SNS topics: {str(e)}',
            'Severity': 'ERROR'
        })
    
    return findings

def main():
    findings = check_monitoring_configuration()
    print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()
