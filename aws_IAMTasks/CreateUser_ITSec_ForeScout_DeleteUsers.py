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
log_file_name = f"itsec-forescout-users-{datetime.now().strftime('%Y%m%d-%H%M')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
    
data_filename = (f"CounterAct-Credentials-"
                   f"{datetime.now().strftime('%Y%m%d-%H%M')}.json")
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "CounterACT_User_Creation\\"
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
        try:
            create_key_response = iam.create_access_key(
                UserName=username
            )['AccessKey']
            print("create_key_response: ", create_key_response)
            self.AccessKey = create_key_response['AccessKeyId']
            self.SecretAccessKey = create_key_response['SecretAccessKey']
        except iam.exceptions.LimitExceededException:
            logger.info("User already has 2 Access Keys registered. Please "
                        "remove an Access Key in order to create a new one.")
            self.AccessKey = "Two Keys Exist for user, unalbe to create key."
            self.SecretAccessKey = "Two Keys Exist for user, unalbe to create key."
            return False
    
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
            return iam_response['User']['UserName']
        except iam.exceptions.EntityAlreadyExistsException:
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
        
    def delete_user(self,userName):
        iam = self.client_config('iam')
        userPolicies = iam.list_user_policies(
            UserName=userName
        )['PolicyNames']
        managedPolicies = iam.list_attached_user_policies(
            UserName=userName
        )['AttachedPolicies']
        accessKeys = iam.list_access_keys(
            UserName=userName
        )['AccessKeyMetadata']
        try:
            if userPolicies:
                for policy in userPolicies:
                    iam.delete_user_policy(
                        UserName=userName,
                        PolicyName=policy
                    )
            if managedPolicies:
                for manpolicy in managedPolicies:
                    iam.detach_user_policy(
                        UserName=userName,
                        PolicyArn=manpolicy['PolicyArn']
                    )
            if accessKeys:
                for accessKey in accessKeys:
                    iam.delete_access_key(
                        UserName=userName,
                        AccessKeyId=accessKey['AccessKeyId']
                    )
            iam.delete_user(
                UserName=userName
            )
        except iam.exceptions.NoSuchEntityException:
            logger.info("No User exists with this Username. Skipping")
            return
        except Exception as e:
            raise e



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
    # targetAccount.create_user("CounterACT")
    targetAccount.delete_user("CounterACT")
#     targetAccount.create_key(targetAccount.UserName)
#     targetAccount.ManageOwnKeyPolicy = json.dumps(manageOwnKeyPolicy)
#     targetAccount.attach_policy(targetAccount.ManageOwnKeyPolicy,
#                                 "TMK_ManageOwnAccessKey")
#     targetAccount.attach_managed_policy(
#         "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess")
#     credential_list[account_ids[account]]= {
#         "AccountId":account,
#         "Username":targetAccount.UserName,
#         "AccessKey":targetAccount.AccessKey,
#         "SecretAccessKey":targetAccount.SecretAccessKey
#     }
    
# with open(attch_completeFilePath, "a") as f:
#     f.write(
#         json.dumps(credential_list, indent=4, default=str)
#     )    
