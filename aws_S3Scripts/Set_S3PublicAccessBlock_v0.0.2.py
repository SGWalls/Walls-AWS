import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


class Account:
    def __init__(self, account_id=None, session=None):
        self.region = 'us-west-2'
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
                os.system(f"aws sso login --profile {self.session.profile_name}")
                return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role('s3_SetPublicAccessBlock') if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, role_name="AWSControlTowerExecution", 
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
                print(results)
                return True
            else:
                print(results)
                return False
        except self.s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
            logger.info('The public access block configuration was not found')
            return False

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
local_filename = os.path.basename(__file__)
local_filename = local_filename.replace(".py","")
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
    f"logs\\{local_filename}\\"
)
log_file_name = f"{local_filename}-{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
logger = create_logger(f'{local_filename}-logger')
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
accnt = Account(account_id="351414345235",session=session)

print(accnt.public_access_blocked)