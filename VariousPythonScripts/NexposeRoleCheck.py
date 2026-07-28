import boto3
import os
import time
import json
import logging
import ipaddress
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


account_list = [
    "030946171726",
    "031714659961",
    "040038112251",
    "089456546922",
    "100774608395",
    "181199587880",
    "203092500943",
    "229844166211",
    "235039969621",
    "276326712482",
    "281040924315",
    "294086801637",
    "296792739314",
    "302548734356",
    "317826648885",
    "482160556746",
    "528955448167",
    "548664465424",
    "615123223256",
    "628165483713",
    "653334254777",
    "669055407494",
    "707253456765",
    "771275968079",
    "781711069557",
    "811569181215",
    "838001389413",
    "856695471500",
    "893243203394",
    "896172592430",
    "899738559321",
    "949438370263",
    "985195195623"
]
userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "NexposeRoleValidation\\"
)
log_file_name = f"nexpose-role-validation-{datetime.now().strftime('%Y%m%d-%H%M')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


def delimiter(symbol='='):
    logger.info(symbol * 120)

def create_filter(name=None, values=None):
    if values is None:
        values = []
    return {
        "Name": name,
        "Values": values
    }

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

def get_accounts(session):
    org = session.client('organizations')
    account_list = []
    paginator = org.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for accId in page['Accounts']:
            if accId['Status'] == 'ACTIVE':
                account_list.append(accId['Id'])
    return account_list


class Account:
    def __init__(self, account_id=None, session=None, role = None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.roleName = role
        self.credentials = self.get_credentials(roleName=self.roleName)

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

    def get_credentials(self,roleName):
        return self.assume_role('nexposeRoleQuery',role_name=roleName) if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, 
                    role_name="OrganizationAccountAccessRole", 
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

    def check_role(self):
        iam = self.client_config("iam")
        try:
            response = iam.get_role(
                RoleName='NexposeDiscovery'
            )['Role']
            if response['RoleName']:
                logger.info(f"=== Account {self.account_id} has a Nexpose Role ===")
        except iam.exceptions.NoSuchEntityException as e:
            logger.info(
                f"!!! Account {self.account_id} does not have a Nexpose Role !!!")

logger = create_logger('validateNexposeRoles')
leg_session = boto3.Session(profile_name='master',region_name='us-west-2')
ct_session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
try:
    token_test = ct_session.client('sts').get_caller_identity()
except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
    if "expired or is otherwise invalid" in str(e):
        delimiter()
        logger.info(e)
        logger.info("Reinitiating SSO Login...")
        os.system(f"aws sso login --profile {ct_session.profile_name}")

ct_account_list = get_accounts(ct_session)
leg_account_list = get_accounts(leg_session)

for account in account_list:
    if account in leg_account_list:
        session = leg_session
        roleName = 'OrganizationAccountAccessRole'
    elif account in ct_account_list:
        session = ct_session
        roleName = 'AWSControlTowerExecution'
    else:
        logger.info(f"~~~ Account {account} is not active. ~~~")
        continue
    accnt = Account(account_id=account,session=session,role=roleName)
    accnt.check_role()
