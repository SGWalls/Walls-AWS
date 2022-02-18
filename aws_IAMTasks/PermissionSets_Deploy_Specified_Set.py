import boto3
import json
import os
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def delimiter(symbol='='):
    logger.info(symbol * 120)


logger = logging.getLogger()
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
while True:
    principalType = input("Delegate access to User or Group? ").upper()
    if principalType == "USER":
        break
    elif principalType == "GROUP":
        break
    else:
        print(" Must be value: 'GROUP' or 'USER' ")
target_accounts = input("Specify Account IDs to target: "
                        "(List IDs separated by comma, or type 'all' to target"
                        " all accounts):  ").split(',')
targetArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-f67c187530befbb2"
targetPrincipalId = "92671d59e0-c51240cb-b4fd-43c1-a939-88e961513dec"

instanceArn = "arn:aws:sso:::instance/ssoins-79079927a28f782f"
NetAdminArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-b64ea37b0be435ff"
itOpsArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-b8fbd7e7a7e29b51"
opsGroupId = "92671d59e0-8c249300-7e54-4719-a410-0577a8101e2a"
firewallArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-9c1582a32cdfb5ee"
firewallGroupId = "92671d59e0-129ebfd1-ea41-4914-bded-7eab9f7b1f43"
principalId = "92671d59e0-cb56c9d7-1b8f-4b3a-a79b-5ce7d9346ef7"
groupId = "92671d59e0-f35323bd-cb4b-4339-b662-581251d2bd4a"
# target_accounts = [
#     '803769386525',
#     '082192703757',
#     '329571145475',
#     '047787824797',
#     '723219059542'
# ]

paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
for page in iterator:
    for account in page['Accounts']:
        accounts.append(account['Id'])
paginator = sso.get_paginator('list_permission_sets')
iterator = paginator.paginate(InstanceArn=instanceArn)
pset_list = []
for page in iterator:
    for pset in page['PermissionSets']:
        pset_list.append(pset)
PrincipalSecArch = [ pset for pset in pset_list if sso.describe_permission_set(InstanceArn=instanceArn,PermissionSetArn=pset)['PermissionSet']['Name'] == "TMK_ITSec_PrincipalSecArchitect" ]

for accountId in accounts:
    permission_sets = sso.list_permission_sets_provisioned_to_account(
        InstanceArn=instanceArn,
        AccountId=accountId
    ).get('PermissionSets')
    if ((targetArn not in permission_sets) and (accountId or "all" in target_accounts)):
        # continue
        print(f"{accountId} does not contains the target Permission Set")
        updated_accounts['Accounts'].append(accountId)
        print(f"Delegating access for Account: {accountId}")
        assignment_request = sso.create_account_assignment(
            InstanceArn=instanceArn,
            TargetId=accountId,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=targetArn,
            PrincipalType='GROUP',
            PrincipalId=targetPrincipalId
        )['AccountAssignmentCreationStatus']
    

current_time = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
file_directory = "C:\\Users\\sgwalls\\Documents\\AWS_Projects\\AWS_Tasks"
file_name = f"Added_PermissionSet_{current_time}.json"
directory = os.path.normpath(file_directory)
file = file_name
filepath = os.path.join(directory,file)
with open(filepath, 'w', encoding='utf-8') as f:
    json.dump(updated_accounts,f, ensure_ascii=False, indent=4, default=str)
