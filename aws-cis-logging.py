import boto3
import json

def check_logging_configuration():
    """Check logging-related CIS controls"""
    findings = []
    
    # Check CloudTrail configuration
    cloudtrail = boto3.client('cloudtrail')
    s3 = boto3.client('s3')
    
    try:
        trails = cloudtrail.describe_trails()['trailList']
        if not trails:
            findings.append({
                'Control': '2.1',
                'Finding': 'No CloudTrail trails configured',
                'Severity': 'CRITICAL'
            })
        
        for trail in trails:
            # Check if CloudTrail is enabled and logging
            try:
                status = cloudtrail.get_trail_status(Name=trail['Name'])
                if not status['IsLogging']:
                    findings.append({
                        'Control': '2.2',
                        'Finding': f"CloudTrail {trail['Name']} is not logging",
                        'Severity': 'CRITICAL'
                    })
            except Exception as e:
                findings.append({
                    'Control': '2.2',
                    'Finding': f"Error checking trail status for {trail['Name']}: {str(e)}",
                    'Severity': 'ERROR'
                })
            
            # Check CloudTrail encryption
            if not trail.get('KmsKeyId'):
                findings.append({
                    'Control': '2.7',
                    'Finding': f"CloudTrail {trail['Name']} is not encrypted with KMS",
                    'Severity': 'HIGH'
                })
            
            # Check S3 bucket logging
            bucket_name = trail['S3BucketName']
            try:
                bucket_logging = s3.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in bucket_logging:
                    findings.append({
                        'Control': '2.6',
                        'Finding': f"S3 bucket {bucket_name} for CloudTrail does not have access logging enabled",
                        'Severity': 'MEDIUM'
                    })
            except Exception as e:
                findings.append({
                    'Control': '2.6',
                    'Finding': f"Error checking S3 bucket logging for {bucket_name}: {str(e)}",
                    'Severity': 'ERROR'
                })
            
    except Exception as e:
        findings.append({
            'Control': '2.1',
            'Finding': f'Error checking CloudTrail configuration: {str(e)}',
            'Severity': 'ERROR'
        })
    
    # Check CloudWatch Logs configuration
    logs = boto3.client('logs')
    try:
        log_groups = logs.describe_log_groups()['logGroups']
        cloudtrail_logs_found = False
        for group in log_groups:
            if 'cloudtrail' in group['logGroupName'].lower():
                cloudtrail_logs_found = True
                break
        
        if not cloudtrail_logs_found:
            findings.append({
                'Control': '2.4',
                'Finding': 'No CloudWatch Log groups found for CloudTrail logs',
                'Severity': 'HIGH'
            })
    except Exception as e:
        findings.append({
            'Control': '2.4',
            'Finding': f'Error checking CloudWatch Logs configuration: {str(e)}',
            'Severity': 'ERROR'
        })

    return findings

def main():
    findings = check_logging_configuration()
    print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()
