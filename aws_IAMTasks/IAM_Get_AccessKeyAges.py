import boto3
import csv
from datetime import datetime, timezone
import subprocess
import os

def refresh_sso_token(profile_name):
    try:
        subprocess.run(['aws', 'sso', 'login', '--profile', profile_name], check=True)
        print(f"SSO token refreshed for profile {profile_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to refresh SSO token: {e}")
        exit(1)

def get_session(profile_name):
    session = boto3.Session(profile_name=profile_name,region_name='us-west-2')
    sts = session.client('sts')
    
    try:
        sts.get_caller_identity()
    except Exception:
        print(f"Session token invalid or expired. Refreshing...")
        refresh_sso_token(profile_name)
        session = boto3.Session(profile_name=profile_name)    
    return session

def get_member_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    
    return accounts

def check_access_keys(iam_client):
    users_with_keys = []
    paginator = iam_client.get_paginator('list_users')
    
    for page in paginator.paginate():
        for user in page['Users']:
            access_keys = iam_client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            
            for key in access_keys:
                last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                
                if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                    last_used_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                else:
                    last_used_date = key['CreateDate']
                
                age = (datetime.now(timezone.utc) - last_used_date).days
                
                users_with_keys.append({
                    'UserName': user['UserName'],
                    'AccessKeyId': key['AccessKeyId'],
                    'CreateDate': key['CreateDate'],
                    'LastUsedDate': last_used_date,
                    'LastUsedRegion': last_used['AccessKeyLastUsed'].get('Region', 'N/A'),
                    'Age': age,
                    'OverNinetyDays': 'Yes' if age > 90 else 'No'
                })
    
    return users_with_keys

def main():
    profile_name = 'ct_master'
    role_name = 'AWSControlTowerExecution'
    output_file = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports\access_key_report.csv'
    
    session = get_session(profile_name)
    org_client = session.client('organizations')
    
    member_accounts = get_member_accounts(org_client)
    
    results = []
    
    for account in member_accounts:
        print(f"Checking account: {account['Id']}")
        
        sts_client = session.client('sts')
        if account['Status'] == 'ACTIVE':
            assumed_role = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{account['Id']}:role/{role_name}",
                RoleSessionName="AccessKeyAudit"
            ) if account['Id'] != '662627786878' else None
        
            assumed_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            ) if assumed_role else session 
            iam_client = assumed_session.client('iam')
            
            users_with_keys = check_access_keys(iam_client)
            
            for user in users_with_keys:
                results.append({
                    'AccountId': account['Id'],
                    'UserName': user['UserName'],
                    'AccessKeyId': user['AccessKeyId'],
                    'CreateDate': user['CreateDate'],
                    'LastUsedDate': user['LastUsedDate'],
                    'LastUsedRegion': user['LastUsedRegion'],
                    'Age': user['Age'],
                    'OverNinetyDays': user['OverNinetyDays']
                })
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['AccountId', 'UserName', 'AccessKeyId', 'Age', 'OverNinetyDays']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    
    print(f"Report generated: {output_file}")

if __name__ == "__main__":
    main()
