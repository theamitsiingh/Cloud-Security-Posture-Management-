import boto3
import json

def check_s3_public_access():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        acl = s3.get_public_access_block(Bucket=bucket_name)
        
        if not acl.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls', True):
            print(f'[!] S3 Bucket {bucket_name} is publicly accessible!')
            # Auto-remediation: Block public access
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f'[-] Public access blocked for {bucket_name}')
        else:
            print(f'[+] S3 Bucket {bucket_name} is secure.')

def check_security_groups():
    ec2 = boto3.client('ec2')
    security_groups = ec2.describe_security_groups()['SecurityGroups']
    
    for sg in security_groups:
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    print(f'[!] Security Group {sg["GroupId"]} allows unrestricted access on port {rule.get("FromPort", "All")}.')
                    # Auto-remediation: Remove rule
                    ec2.revoke_security_group_ingress(
                        GroupId=sg['GroupId'],
                        IpPermissions=[rule]
                    )
                    print(f'[-] Removed open access rule from Security Group {sg["GroupId"]}')

def check_rds_encryption():
    rds = boto3.client('rds')
    instances = rds.describe_db_instances()['DBInstances']
    
    for instance in instances:
        if not instance.get('StorageEncrypted', False):
            print(f'[!] RDS Instance {instance["DBInstanceIdentifier"]} is not encrypted!')
        else:
            print(f'[+] RDS Instance {instance["DBInstanceIdentifier"]} is encrypted.')

def check_iam_mfa():
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            print(f'[!] IAM User {user["UserName"]} does not have MFA enabled!')
        else:
            print(f'[+] IAM User {user["UserName"]} has MFA enabled.')

def log_to_security_hub(finding):
    security_hub = boto3.client('securityhub')
    security_hub.batch_import_findings(Findings=[finding])

def generate_report():
    report = {
        "S3": check_s3_public_access(),
        "SecurityGroups": check_security_groups(),
        "RDS": check_rds_encryption(),
        "IAM": check_iam_mfa()
    }
    with open("cspm_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("[+] Security report saved as cspm_report.json")

def main():
    print("Checking AWS Security Posture...")
    check_s3_public_access()
    check_security_groups()
    check_rds_encryption()
    check_iam_mfa()
    generate_report()
    print("Security scan complete.")

if __name__ == "__main__":
    main()
