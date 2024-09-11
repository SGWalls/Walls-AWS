import boto3 
import os
import subprocess, shlex
import logging
import datetime


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\UpdateAWSAccountPWPolicy\\"
    )
log_file_name = f"account-updatePWpolicy-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

class Account():
    def __init__(self, logger=None,account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2"):
        self.logger = logger
        self.region = region
        self.account_id = account_id
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
        self.credentials = self.get_credentials() if account_id != '741252614647' else {
            'AccessKeyId':None,
            'SecretAccessKey':None,
            'SessionToken':None
        }

    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except Exception as e:
            if "expired" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                subprocess.run(shlex.split(
                    f"aws sso login --profile {self.session.profile_name}"
                ))
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

    def resource_config(self, service):
        return self.session.resource(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,)
    
    def update_password_policy(self, password_policy):
        iam = self.client_config('iam')
        try:
            response = iam.update_account_password_policy(**password_policy)
            self.logger.info(f"Password policy updated for account {self.account_id}")
        except Exception as e:
            self.logger.error(f"Error updating password policy for account {self.account_id}: {e}")


def delimiter(symbol='='):
    logger.info(symbol * 120)

def handle_dry_run(error):
    logger.info(f"Operation: {error.operation_name}")
    logger.info(f"{error.response['Error']['Message']}")

def create_logger(logger_name,log_path,log_file_name):
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

def get_accounts(session):
    client = session.client('organizations')
    accounts = []
    response = client.list_accounts()
    accounts.extend(response['Accounts'])
    while 'NextToken' in response:
        response = client.list_accounts(NextToken=response['NextToken'])
        accounts.extend(response['Accounts'])
    return accounts


logger = create_logger('Logging',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master')
Account(logger, '741252614647', session=session).get_caller_account()
account_list = get_accounts(session)
password_policy = {
    'MinimumPasswordLength': 14,
    'RequireSymbols': True,
    'RequireNumbers': True,
    'RequireUppercaseCharacters': True,
    'RequireLowercaseCharacters': True,
    'AllowUsersToChangePassword': True,
    'MaxPasswordAge': 90,
    'PasswordReusePrevention': 5,
    'HardExpiry': False
}

for account in account_list:
    accnt = Account(logger, account['Id'], session)
    accnt.update_password_policy(password_policy)

