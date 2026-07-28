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


# def waiter(function,retries=5,retry=True,*args,**kwargs):
#     counter = 1
#     while retry and counter <= retries:
#         time.sleep(2^counter * .1)
#         response = function(*args,**kwargs)
#         if response['Status'] == 'SUCCEEDED':
#             retry = False
#         else:
#             retry = True
#         counter += 1


# def alt_waiter(function,retries=5,*args,**kwargs):
#     for counter in range(1,retries+1):
#         time.sleep(2^counter * .1)
#         response = function(*args,**kwargs)
#         if response['Status'] == 'SUCCEEDED':
#             return

# def assignment_waiter(requestId):
#     while response['Status'] != 'SUCCEEDED':
#         time.sleep(1)
#         response = sso.describe_account_assignment_creation_status(
#             InstanceArn=instanceArn,
#             AccountAssignmentCreationRequestId=requestId
#         )['AccountAssignmentCreationStatus']


logger = logging.getLogger()
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
instanceArn = "arn:aws:sso:::instance/ssoins-79079927a28f782f"
NetAdminArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-b64ea37b0be435ff"
itOpsArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-b8fbd7e7a7e29b51"
opsGroupId = "92671d59e0-8c249300-7e54-4719-a410-0577a8101e2a"
firewallArn = "arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-9c1582a32cdfb5ee"
firewallGroupId = "92671d59e0-129ebfd1-ea41-4914-bded-7eab9f7b1f43"
principalId = "92671d59e0-cb56c9d7-1b8f-4b3a-a79b-5ce7d9346ef7"
groupId = "92671d59e0-f35323bd-cb4b-4339-b662-581251d2bd4a"
paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
for page in iterator:
    for account in page['Accounts']:
        accounts.append(account['Id'])


for accountId in accounts:
    permission_sets = sso.list_permission_sets_provisioned_to_account(
        InstanceArn=instanceArn,
        AccountId=accountId
    ).get('PermissionSets')
    if not permission_sets:
        # continue
        print(f"!!!{accountId} does not have any permission sets!!!")
        updated_accounts['Accounts'].append(accountId)
        print(f"Delegating NetworkAdministrator access to group for Account: {accountId}")
        sso.create_account_assignment(
            InstanceArn=instanceArn,
            TargetId=accountId,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=NetAdminArn,
            PrincipalType='GROUP',
            PrincipalId=groupId
        )
        print(f"Delegating ITSysOps access to group for Account: {accountId}")
        sso.create_account_assignment(
            InstanceArn=instanceArn,
            TargetId=accountId,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=itOpsArn,
            PrincipalType='GROUP',
            PrincipalId=opsGroupId
        )
        print(f"Delegating FirewallAdmn access to group for Account: {accountId}")
        sso.create_account_assignment(
            InstanceArn=instanceArn,
            TargetId=accountId,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=firewallArn,
            PrincipalType='GROUP',
            PrincipalId=firewallGroupId
        )
    elif NetAdminArn not in permission_sets:
        # continue
        print(f"{accountId} does not contains the NetworkAdministrator Permission Set")
        updated_accounts['Accounts'].append(accountId)
        print(f"Delegating NetworkAdministrator access to group for Account: {accountId}")
        assignment_request = sso.create_account_assignment(
            InstanceArn=instanceArn,
            TargetId=accountId,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=NetAdminArn,
            PrincipalType='GROUP',
            PrincipalId=groupId
        )['AccountAssignmentCreationStatus']
    else:
        net_admin_assignment = sso.list_account_assignments(
            InstanceArn=instanceArn,
            AccountId=accountId,
            PermissionSetArn=NetAdminArn
        )['AccountAssignments'][0]
        if (net_admin_assignment['PrincipalType'] == 'USER' and 
            net_admin_assignment['PrincipalId'] == principalId):
            print(f"{accountId} has NetworkAdministrator delegated to a user")
            print(net_admin_assignment)
            # updated_accounts['Accounts'].append(accountId)
            # print(f"Deleting ADMSJDesmond access from Account: {accountId}")
            # sso.delete_account_assignment(
            #     InstanceArn=instanceArn,
            #     TargetId=accountId,
            #     TargetType='AWS_ACCOUNT',
            #     PermissionSetArn=NetAdminArn,
            #     PrincipalType='USER',
            #     PrincipalId=principalId
            # )
            # print(f"Delegating NetworkAdministrator access to group for Account: {accountId}")
            # sso.create_account_assignment(
            #     InstanceArn=instanceArn,
            #     TargetId=accountId,
            #     TargetType='AWS_ACCOUNT',
            #     PermissionSetArn=NetAdminArn,
            #     PrincipalType='GROUP',
            #     PrincipalId=groupId
            # )

current_time = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
file_directory = "C:\\Users\\sgwalls\\Documents\\AWS_Projects\\AWS_Tasks"
file_name = f"Added_PermissionSet_{current_time}.json"
directory = os.path.normpath(file_directory)
file = file_name
filepath = os.path.join(directory,file)
with open(filepath, 'w', encoding='utf-8') as f:
    json.dump(updated_accounts,f, ensure_ascii=False, indent=4, default=str)

