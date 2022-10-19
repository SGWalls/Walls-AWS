import boto3
import json
import os
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "ITSec_ForeScout_Users\\ITSec_ForeScout_Users_logs\\"
)
log_file_name = f"itsec-forescout-users-{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


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

    def create_key(self,username):
        iam = self.client_config('iam')        
        try:
            create_key_response = iam.create_access_key(
                UserName=username
            )['AccessKey']
            print("create_key_response: ", create_key_response)
            self.AccessKey = create_key_response['AccessKeyId']
            self.SecretAccessKey = create_key_response['SecretAccessKey']
        except self.iam.exceptions.LimitExceededException:
            logger.info("User already has 2 Access Keys registered. Please "
                        "remove an Access Key in order to create a new one.")
            return False
    
    def create_user(self,username):
        iam = self.client_config('iam')        
        try:
            iam_response = iam.create_user(
            UserName=username,
            Tags=[
                {
                    'Key': 'service-request',
                    'Value': service_request if service_request else None
                },
            ]
            )
            return iam_response['User']['UserName']
        except iam.exceptions.EntityAlreadyExistsException:
            return {'UserName':username}

    def attach_policy(self,policy):
        iam = self.client_config('iam')        
        iam.put_user_policy(
            UserName=self.UserName,
            PolicyName=f"{self.UserName}_Access",
            PolicyDocument=policy
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
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def create_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s ::%(levelname)s:: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler = logging.FileHandler(os.path.join(log_path, log_file_name))
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

logger = create_logger('itsec_forescout_users')

service_request = input("What is the Request ID for this request? ")
session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
test_token(session)
org = session.client("organizations")
paginator = org.get_paginator('list_accounts')
page_iterator = paginator.paginate()
account_list = []
for page in page_iterator:
    account_list.extend(page['Accounts'])
account_ids = {item['Id']:item['Name'] for item in account_list}

for account in account_ids.keys():
    targetAccount = Account(account,session)

    pass
