import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from concurrent.futures import ThreadPoolExecutor, as_completed
from retriever import Account
from retriever import get_org_account_list
from retriever import validate_sso_token

userprofile = os.environ["USERPROFILE"]


def list_all_vaults(self):
    backup_client = self.client_config('backup')
    vaults = []
    try:
        paginator = backup_client.get_paginator("list_backup_vaults")
        for page in paginator.paginate():
            vaults.extend(page.get("BackupVaultList", []))
        # print(f"Found {len(vaults)} vault(s)")
        # print (vaults)
        return vaults
    except ClientError as e:
        print(f"Failed to list backup vaults: {e}")
        return None
   

def process_account(account, session):
    print(f"!!! Checking Account: {account['Name']} : {account['Id']} !!!")
    current_account = Account(account_id=account['Id'],
                        session=session,
                        sessionName='ADMSGWalls',
                        roleName='AWSControlTowerExecution',
                        region='us-west-2')
    current_account.accountName = account['Name']
    vault_list = list_all_vaults(current_account)
    if not vault_list:
        print(f"No vaults in {account['Name']}")
        account_detail = {
            {account['Id']} : {account['Name']} 
        }
        missing_accounts_list.append(account_detail)
        return 1
    return 0


logger = logging.getLogger('AWSLogging')
session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)
account_list = get_org_account_list(session)
# account_list = [{
#     "Id":"653334254777",
#     "Name": "Cherwell_Integration"
#     },
#     {
#         "Id":"640168419836",
#         "Name": "PRD_FHL-LegacyApps"
#     }
# ]
# count = 0
# for account in account_list:
#     print(f"!!! Checking Account: {account['Name']} : {account['Id']} !!!")
#     current_account = Account(account_id=account['Id'],
#                         session=session,
#                         sessionName='ADMSGWalls',
#                         roleName='AWSControlTowerExecution',
#                         region='us-west-2')
#     current_account.accountName = account['Name']
#     vault_list = list_all_vaults(current_account)
#     if not vault_list:
#         count += 1
#         print(f"No vaults in {account['Name']}")
    
#         backup_client = current_account.client_config('backup')
        # try:
        #     response = backup_client.create_backup_vault(
        #         BackupVaultName=f"Default"
        #     )
        #     print(response)
        # except Exception as e:
        #     print(f"Error creating vault: {e}")

count = 0
missing_accounts_list = []
with ThreadPoolExecutor(max_workers=10) as executor:
    future_to_account = {executor.submit(process_account, account, session): account 
                        for account in account_list}
    
    for future in as_completed(future_to_account):
        account = future_to_account[future]
        try:
            result = future.result()
            count += result
        except Exception as e:
            print(f"Account {account['Name']} generated an exception: {e}")

print(count)
print(missing_accounts_list)
