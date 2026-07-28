import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


class Account:
    def __init__(self, account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2"):
        self.region = region
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
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
    
    def get_users(self):
        return
    
    def get_access_keys(self,userName):
        return
    
    def get_access_key_age(self,accessKeyId):
        return


def delimiter(symbol='='):
    logger.info(symbol * 120)

logger = logging.getLogger('Logging')

