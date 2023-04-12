import boto3
import json
import os
import logging
import time
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "ITSec_ForeScout_Users\\ITSec_ForeScout_Users_logs\\"
)
log_file_name = f"itsec-forescout-users-{datetime.now().strftime('%Y%m%d-%H%M')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
    
data_filename = (f"CounterAct-Credentials-"
                   f"{datetime.now().strftime('%Y%m%d-%H%M')}.json")
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "ITSec_ForeScout_Users\\"
)
if not os.path.exists(export_path):
    os.makedirs(export_path)
attch_completeFilePath = os.path.join(export_path, data_filename)


manageOwnKeyPolicy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowManageOwnAccessKeys",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:DeleteAccessKey",
                    "iam:ListAccessKeys",
                    "iam:UpdateAccessKey"
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}"
            }
        ]
    }


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
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        logger.info(access_keys)
        if access_keys:
            try: 
                for access_key in access_keys:
                    access_key_id = access_key['AccessKeyId']
                    access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key_id)  
                    if access_key_last_used['AccessKeyLastUsed'].get('LastUsedDate'):
                        last_used_time = access_key_last_used['AccessKeyLastUsed']['LastUsedDate']
                        if datetime.now(timezone.utc) - last_used_time > timedelta(days=30):
                            logger.info("Keys have not been used in the past"
                            "30 days.  Creating new Keys.")
                            create_key_response = iam.create_access_key(
                            UserName=username
                            )['AccessKey']
                            self.AccessKey = create_key_response['AccessKeyId']
                            self.SecretAccessKey = create_key_response['SecretAccessKey']
                        else:
                            logger.info("User already has a set of valid Keys.")
                            self.AccessKey = "Valid Keys already exist for user."
                            self.SecretAccessKey = "Valid Keys already exist for user."
                    elif datetime.now(timezone.utc) - access_key['CreateDate'] < timedelta(days=1):
                        logger.info("!!!Access Key less than 1 day old. Deleting Keys!!!")
                        iam.delete_access_key(
                            UserName=username,
                            AccessKeyId=access_key_id
                        )
                        logger.info(f"!!!Key {access_key_id} Deleted!!!")
                        self.AccessKey = "Ignore"
                        self.SecretAccessKey = "Ignore"
                    else:
                        logger.info("User already has a set of valid Keys.")
                        self.AccessKey = "Valid Keys already exist for user."
                        self.SecretAccessKey = "Valid Keys already exist for user."
            except iam.exceptions.LimitExceededException:
                logger.info("User already has 2 Access Keys registered. Please "
                            "remove an Access Key in order to create a new one.")
                self.AccessKey = "Two Keys Exist for user, unalbe to create key."
                self.SecretAccessKey = "Two Keys Exist for user, unalbe to create key."
                return False
        else:
            logger.info("User does not currently have any keys. Creating new Keys.") 
            create_key_response = iam.create_access_key(
                            UserName=username
                        )['AccessKey']
            self.AccessKey = create_key_response['AccessKeyId']
            self.SecretAccessKey = create_key_response['SecretAccessKey']
    
    def create_user(self,username):
        iam = self.client_config('iam')        
        try:
            iam_response = iam.create_user(
            UserName=username,
            Tags=[
                {
                    'Key': 'service-request',
                    'Value': service_request if service_request else ""
                },
            ] 
            )
            self.UserName = username
            logger.info(f"IAM User Successfully Created!")
            return iam_response['User']['UserName']
        except iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"A user with the name {username} already Exists!")
            self.UserName = username
            return {'UserName':username}

    def attach_policy(self,policy,policy_name=None):
        iam = self.client_config('iam')        
        iam.put_user_policy(
            UserName=self.UserName,
            PolicyName=policy_name if policy_name 
                       else f"{self.UserName}_Access",
            PolicyDocument=policy
        )

    def attach_managed_policy(self,policyArn):
        iam = self.client_config('iam')
        iam.attach_user_policy(
            UserName=self.UserName,
            PolicyArn=policyArn
        )



def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session=boto3):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if ("expired or is otherwise invalid" in str(e) or 
            "Token has expired and refresh failed" in str(e)):
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
credential_list = {}
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
# account_ids = {
#     "874595533236":"Sandbox_2",
#     "427475715700":"DEV_ExtFileTransfer_Services"
# }

for account in account_ids.keys():
    targetAccount = Account(account,session)
    logger.info(delimiter())
    logger.info(f"Starting user creation for account with ID {account}. . .")
    targetAccount.create_user("CounterACT")
    logger.info(f"Checking/Creating Access Key and Secret Key for user. . .")
    targetAccount.create_key(targetAccount.UserName)
    targetAccount.ManageOwnKeyPolicy = json.dumps(manageOwnKeyPolicy)
    targetAccount.attach_policy(targetAccount.ManageOwnKeyPolicy,
                                "TMK_ManageOwnAccessKey")
    targetAccount.attach_managed_policy(
        "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess")
    logger.info(f"IAM User and Keys processed successfully for account "
           f"with id {account}")
    credential_list[account_ids[account]]= {
        "AccountId":account,
        "Username":targetAccount.UserName,
        "AccessKey":targetAccount.AccessKey,
        "SecretAccessKey":targetAccount.SecretAccessKey
    }
    
with open(attch_completeFilePath, "a") as f:
    f.write(
        json.dumps(credential_list, indent=4, default=str)
    )    
