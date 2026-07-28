import boto3
import json
import os
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


byol_codes = [
    "RunInstances:00g0",
    "RunInstances:0800"
]

class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()


    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
            if "expired or is otherwise invalid" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                os.system(f"aws sso login --profile {self.session.profile_name}")
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

    def get_ec2_details(self):
        ec2 = self.client_config('ec2')
        instance_list = []
        for reservation in ec2.describe_instances()['Reservations']:
            for instance in reservation['Instances']:
                if instance['UsageOperation'] not in byol_codes:
                    instance_list.append(instance['InstanceId'])
        self.instances = instance_list



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
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


logger = logging.getLogger('s3_SetPublicAccessBlock')
logger.setLevel(logging.INFO)
region = 'us-west-2'


session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
test_token(session)
org = session.client("organizations")
paginator = org.get_paginator('list_accounts')
page_iterator = paginator.paginate()

account_list = []
for page in page_iterator:
    account_list.extend(page['Accounts'])
account_ids = {item['Id']:item['Name'] for item in account_list}
total_instance_list = []
for account in account_ids.keys():

    target_account = Account(account_id=account,session=session,region=region)
    target_account.get_ec2_details()
    total_instance_list.extend(target_account.instances)

print(total_instance_list)
# instance_list = []
# for reservation in ec2.describe_instances()['Reservations']:
#     for instance in reservation['Instances']:
#         if instance['UsageOperation'] not in byol_codes:
#             instance_list.append(instance)


