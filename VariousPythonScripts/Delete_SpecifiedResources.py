import boto3
import json
import os
import logging
import pandas as pd
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "delete_resources\\resource_deletion_logs\\"
)
log_file_name = f"remove_tgw-attachment{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

session = boto3.Session(profile_name="ct_master",region_name="us-west-2")
account_list = [
    "025693222982",
    "071284598090",
    "242203395629",
    "422790514063",
    "491074083512",
    "499166352453",
    "717322314148",
    "738683365990",
    "804361615171",
    "874595533236",
    "896172592430",
    "919799598487",
    "939781381405"
]
# account_list = [
#      "025693222982"
# ]

function_names = [
    "CloudFlowExternalIdGeneration",
    "CloudFlowOnboardingNotification"
]

iam_prefix = "StackSet-POC-AlgoSec"

class Account:
    def __init__(self, account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2"):
        self.region = region
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id
        self.get_caller_account()
        self.credentials = self.get_credentials()

    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except Exception as e:
            if "expired" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                os.system(f"aws sso login --profile {self.session.profile_name}")
                return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role(self.sessionName) if (
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

    def delete_lambda(self, functionName):
        lmbda = self.client_config('lambda') 
        try:
            logger.info(f"Deleting function with the name {functionName}")
            lmbda.delete_function(FunctionName=functionName)
            logger.info(f". . .{functionName} Deleted. . .")
        except Exception as e:
            logger.info(f"Lambda With the name {functionName} does not exist!")
        
    def delete_iam_role(self,roleName):
        iam = self.client_config('iam')
        try:
            logger.info(f"deleting the IAM Role with name {roleName}")
            iam.delete_role(RoleName=roleName)
            logger.info(f". . . {roleName} Deleted . . .")
        except Exception as e:
            logger.info(e)
        
def create_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
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


def delimiter(symbol='='):
    logger.info(symbol * 120)

logger = create_logger('Logging')

for account in account_list:
    accnt = Account(
        account_id=account,
        session = session
    )
    for function_name in function_names:
        accnt.delete_lambda(function_name)

    for role in [r for r in accnt.client_config('iam').list_roles()['Roles'] if r['RoleName'].startswith(iam_prefix)]:
        accnt.delete_iam_role(role['RoleName'])
