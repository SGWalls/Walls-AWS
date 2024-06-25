import boto3
import json
import os
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

SSO_INSTANCE = "arn:aws:sso:::instance/ssoins-79079927a28f782f"


class SSOInstance():
    def __init__(self, sso_instance_arn, admin_session) -> None:
        self.client = admin_session.client('sso-admin')
        self.InstanceArn = sso_instance_arn
    
    def list_permission_sets_provisioned_to_account(self, AccountId):
        return self.client.list_permission_sets_provisioned_to_account(
            InstanceArn=self.InstanceArn,
            AccountId=AccountId
        )

    def create_account_assignment(self, 
                                  Target_Id, 
                                  PermissionSet_Arn, 
                                  Principal_Id,
                                  Principal_Type='GROUP', 
                                  Target_Type='AWS_ACCOUNT', 
                                  ):
        return self.client.create_account_assignment(
                InstanceArn=self.InstanceArn,
                TargetId=Target_Id,
                TargetType=Target_Type,
                PermissionSetArn=PermissionSet_Arn,
                PrincipalType=Principal_Type,
                PrincipalId=Principal_Id
            )


class Account():
    def __init__(self, accountId, ssoInstance=None) -> None:
        self.accountId = accountId
        if ssoInstance:
            self.ssoInstance = ssoInstance
        
    def list_account_assignments(self, permissionSet_Arn):
        if permissionSet_Arn:
            try:
                return self.ssoInstance.client.list_account_assignments(
                    InstanceArn=self.ssoInstance.InstanceArn,
                    AccountId=self.accountId,
                    PermissionSetArn=permissionSet_Arn
                )
            except self.ssoInstance.client.exceptions.ResourceNotFoundException as e:
                print("Permission Set is not assigned to account.")
        else:
            print("!! No Permission Set ARN provided !!")

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
paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
for page in iterator:
    for account in page['Accounts']:
        accounts.append(account)

permissionSetArn = input("Enter the Permission Set ID to be depoloyed: ")
permissionSetArn = f"arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/{permissionSetArn}"
groupId = input("Enter the ID of the Principal that will be delgated access: ")
# groupId = "92671d59e0-f0e212ad-07fe-468d-919a-d09f857ec194"


ctSSO = SSOInstance(SSO_INSTANCE,session)
for account in accounts:
    accnt1 = Account(account['Id'],ctSSO)
    accnt1.inScope = True
    accnt1.assignments = accnt1.list_account_assignments(permissionSetArn)
    if accnt1.assignments['AccountAssignments']:
        for assignment in accnt1.assignments['AccountAssignments']:
            if assignment['PrincipalId'] == groupId:
                # print(f"removing account {account} from scope")
                accnt1.inScope = False
    if accnt1.inScope:
        # print(f"adding permissions set to account {account}")
        # ctSSO.create_account_assignment(accnt1.accountId,
        #                                 permissionSetArn,
        #                                 groupId)
        print(f"Permission not deployed to Account {account['Name']} : {account['Id']}")
    