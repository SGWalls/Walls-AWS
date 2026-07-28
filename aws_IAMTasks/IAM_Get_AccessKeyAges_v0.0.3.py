import boto3
import csv
from datetime import datetime, timezone
import subprocess, shlex
import concurrent.futures
from botocore.exceptions import ClientError

def refresh_sso_token(profile_name):
    try:
        subprocess.run(shlex.split(
            f"aws sso login --profile {profile_name}"
        ))
        print(f"SSO token refreshed for profile {profile_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to refresh SSO token: {e}")
        exit(1)

def get_session(profile_name):
    session = boto3.Session(profile_name=profile_name)
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
                try:
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    
                    if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                        last_used_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                    else:
                        last_used_date = 'Never Used'

                    if last_used_date == 'Never Used':
                        days_since_last_use = float('inf')  # Set to infinity if never used
                    else:
                        days_since_last_use = (datetime.now(timezone.utc) - last_used_date).days
                    age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    
                    users_with_keys.append({
                        'UserName': user['UserName'],
                        'AccessKeyId': key['AccessKeyId'],
                        'CreateDate': key['CreateDate'],
                        'LastUsedDate': last_used_date,
                        'LastUsedRegion': last_used['AccessKeyLastUsed'].get('Region', 'N/A'),
                        'Age': age,
                        'OverNinetyDays': 'Yes' if age > 90 else 'No',
                        'UnusedLastNinetyDays': 'Yes' if days_since_last_use > 90 else 'No'
                    })
                except ClientError as e:
                    print(f"Error processing key {key['AccessKeyId']} for user {user['UserName']}: {e}")
    
    return users_with_keys

def check_account(account, role_name, master_session):
    print(f"Checking account: {account['Id']}")
    
    sts_client = master_session.client('sts')
    if account['Status'] == 'ACTIVE':
        try:
            assumed_role = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{account['Id']}:role/{role_name}",
                RoleSessionName="AccessKeyAudit"
            ) if account['Id'] != '662627786878' else None
            
            assumed_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            ) if assumed_role else master_session
            
            iam_client = assumed_session.client('iam')
            
            users_with_keys = check_access_keys(iam_client)
            
            return [(account['Id'], user) for user in users_with_keys]
        except Exception as e:
            print(f"Error checking account {account['Id']}: {e}")
            return []
    else:
        print(f"Skipping inactive account {account['Id']}")
        return []
def main():
    profile_name = 'ct_master'
    role_name = 'AWSControlTowerExecution'
    output_file = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports\access_key_report.csv'
    
    session = get_session(profile_name)
    org_client = session.client('organizations')
    
    member_accounts = get_member_accounts(org_client)
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_account = {executor.submit(check_account, account, role_name, session): account for account in member_accounts}
        for future in concurrent.futures.as_completed(future_to_account):
            results.extend(future.result())
    
    while True:
        try:
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = ['AccountId', 'UserName', 'AccessKeyId', 'CreateDate','LastUsedDate','LastUsedRegion','Age', 'OverNinetyDays','UnusedLastNinetyDays']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
                
                writer.writeheader()
                for account_id, user in results:
                    row = {'AccountId': account_id, **user}
                    writer.writerow(row)
                break
        except PermissionError:
            input(f"Please close the file {output_file} and press Enter to continue...")

    # with open(output_file, 'w', newline='') as csvfile:
    #     fieldnames = ['AccountId', 'UserName', 'AccessKeyId', 'CreateDate','LastUsedDate','LastUsedRegion','Age', 'OverNinetyDays']
    #     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
    #     writer.writeheader()
    #     for account_id, user in results:
    #         row = {'AccountId': account_id, **user}
    #         writer.writerow(row)
    
    print(f"Report generated: {output_file}")

if __name__ == "__main__":
    main()

