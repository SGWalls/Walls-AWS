import boto3
import logging
import os
from retriever import validate_sso_token, get_org_account_list, Account


class Account:
    def __init__(self, account_id=None, session=None, sessionName='AdminTask',
                 roleName = 'ent-cloudops_resource-discovery', region="us-west-2"):
        self.region = region
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
        self.roleName = roleName
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
        return self.assume_role(self.sessionName, self.roleName)

    def assume_role(self, session_name, 
                    role_name, 
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



def delimiter(symbol='='):
    logger.info(symbol * 120)

logger = logging.getLogger('Logging')

session = boto3.Session(profile_name='audit_discover',region_name='us-west-2')
account_list = get_org_account_list(session)

for account in account_list:
    if account['Id'] != '662627786878':
       print(account['Id'])
        # current_account = Account(account['Id'],session=session,sessionName='ADMSGWALLS@globe.life',roleName='ent-cloudops_resource-discovery')
        # current_account.ec2  = current_account.client_config('ec2')
        # print(current_account.ec2.describe_network_interfaces(MaxResults=10)
        # )
    


