import boto3
import json
import os
import sys
import logging
import subprocess, shlex
import urllib3
from datetime import datetime
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)
from helpers.helper import validate_sso_token as test_token
from helpers.helper import create_logger
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

http = urllib3.PoolManager(
    maxsize=10,
    retries=urllib3.Retry(3, backoff_factor=0.1)
)
userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "logging\\S3_PublicAccessBlock\\"
)
log_file_name = f"s3-publicaccessblock-{datetime.now().strftime('%Y%m%d-%H%M')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


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
        logger.info(f"Enabling public access block for account {self.account_id}")
        self.s3control.put_public_access_block(
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            },
            AccountId=self.account_id
        )
        logger.info(f"Public access block enabled for account {self.account_id}")


def delimiter(symbol='='):
    logger.info(symbol * 120)


# def test_token(session=boto3):
#     client = session.client('sts')
#     try:
#         client.get_caller_identity()
#     except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
#         if "expired or is otherwise invalid" in str(e):
#             delimiter()
#             logger.info(e)
#             logger.info("Reinitiating SSO Login...")
#             subprocess.run(shlex.split(f"aws sso login --profile {session.profile_name}")) # import subprocess, shlex
#     return 

def process_account(account_id, session, region):
    target_account = Account(account_id=account_id, session=session, region=region)
    logger.info(f"Processing account {account_ids[target_account.account_id]}")
    if not target_account.public_access_blocked:
        print(account_ids[target_account.account_id])
        target_account.put_public_block()

def get_account_list(org_client):
    account_list = []
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate(PaginationConfig={'PageSize': 20}):
            account_list.extend(page['Accounts'])
    except Exception as e:
        logger.error(f"Error fetching accounts: {e}")
        raise
    return account_list

logger = create_logger('S3_PublicAccessBlock', log_path, log_file_name)
logger.setLevel(logging.INFO)
region = 'us-west-2'


session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
test_token(session)

org = session.client("organizations")
logger.info("Retrieving account list...")
paginator = org.get_paginator('list_accounts')
page_iterator = paginator.paginate()
account_list = []
for page in page_iterator:
    account_list.extend(page['Accounts'])
logger.info("Account list retrieved. Filtering List. . .")
excempt_id = session.client("sts").get_caller_identity()['Account']
account_ids = {item['Id']:item['Name'] for item in account_list if (item['Status'] == 'ACTIVE' and item['Id'] != excempt_id)}
logger.info("Account list filtered. Processing List. . .")
# for account in account_ids.keys():

#     target_account = Account(account_id=account,session=session,region=region)
#     if not target_account.public_access_blocked:
#         print(account_ids[target_account.account_id])
#         target_account.put_public_block()
max_workers = 10  # Adjust based on your needs
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_account, account, session, region) 
               for account in account_ids.keys()]
    for future in as_completed(futures):
        try:
            future.result()
        except Exception as e:
            logger.error(f"Error processing account: {e}")    