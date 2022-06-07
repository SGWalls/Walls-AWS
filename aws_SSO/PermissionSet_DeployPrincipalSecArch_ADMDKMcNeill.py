from typing import Type
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

def deploy_permission(target,permissionArn,principalType,principalId):
    sso.create_account_assignment(
        InstanceArn=instanceArn,
        TargetId=target,
        TargetType='AWS_ACCOUNT',
        PermissionSetArn=permissionArn,
        PrincipalType=principalType,
        PrincipalId=principalId
    )


def delimiter(symbol='='):
    logger.info(symbol * 120)


logger = logging.getLogger()
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
instanceArn = "arn:aws:sso:::instance/ssoins-79079927a28f782f"
PrincipalSecArch = 'arn:aws:sso:::permissionSet/ssoins-79079927a28f782f/ps-b5d2ad84f30c3a3e'
dougADM = '92671d59e0-2df86e07-101d-4506-96a3-511fe47f5e0a'
target_accounts = input("Which accounts does Doug need access to? ")
target_accounts = target_accounts.split(',')


for account in target_accounts:
    deploy_permission(
        target=account,
        permissionArn=PrincipalSecArch,
        principalType='USER',
        principalId=dougADM
    )