import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()

    def get_credentials(self):
        return self.assume_role('ent_setS3AccountPubBlock')

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

    def s3_account_pab(self):
        s3control = self.client_config('s3control')
        try:
            publicAccessSetting =  s3control.get_public_access_block(
                AccountId=self.account_id
            )['PublicAccessBlockConfiguration']
        except s3control.exceptions.NoSuchPublicAccessBlockConfiguration as e:
            logger.info("Account does not have any Public Access Block configurations")
            publicAccessSetting = {
                    'PublicAccessBlock': False                
            }
        if not all(publicAccessSetting.values()):
            logger.info("Putting Public Access Block. . .")
            s3control.put_public_access_block(
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                },
                AccountId=self.account_id
            )
        else:
            logger.info("Public Access Block Already Enabled.")
        return


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



userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "S3_PutPublicAccessBlockLogs\\"
)
log_file_name = f"S3-put-public-access-block-{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

logger = create_logger('s3PutPABLogger')
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
pub_lbs = {}
for page in iterator:
    for account in page['Accounts']:
        accounts.append(account['Id'])

for account in accounts:
    logger.info(f"Beginning to process Account: {account}")
    if account != "662627786878":
        logger.info(f"Processing Account {account}")
        accnt = Account(account,session)
        accnt.s3_account_pab()
