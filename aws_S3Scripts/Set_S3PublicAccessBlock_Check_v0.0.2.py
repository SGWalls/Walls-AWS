import boto3
import json
import os
import logging
import subprocess, shlex
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()
        self.s3control = self.client_config('s3control')
        self.public_access_blocked = self.query_public_access_block()

    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
            if "expired or is otherwise invalid" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                subprocess.run(shlex.split(f"aws sso login --profile {self.session.profile_name}"))
                return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role('s3_SetPublicAccessBlock') if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )

    def query_public_access_block(self):
        try:
            results = self.s3control.get_public_access_block(
                AccountId=self.account_id
            )
            results = results['PublicAccessBlockConfiguration']
            if all(results.values()):
                # print(results)
                return True
            else:
                print(results)
                return False
        except self.s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
            logger.info('The public access block configuration was not found')
            return False
    
    def put_public_block(self):
        self.s3control.put_public_access_block(
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            },
            AccountId=self.account_id
        )


def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session=boto3):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            subprocess.run(shlex.split(f"aws sso login --profile {session.profile_name}")) # import subprocess, shlex
    return 


logger = logging.getLogger('s3_SetPublicAccessBlock')
logger.setLevel(logging.INFO)
region = 'us-west-2'


session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
test_token(session)

org = session.client("organizations")

paginator = org.get_paginator('list_accounts')
page_iterator = paginator.paginate()
account_list = []
for page in page_iterator:
    account_list.extend(page['Accounts'])
account_ids = {item['Id']:item['Name'] for item in account_list}

for account in account_ids.keys():

    target_account = Account(account_id=account,session=session,region=region)
    if not target_account.public_access_blocked:
        print(account_ids[target_account.account_id])
    