import boto3
import configparser
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


class Account:
    def __init__(self, account_id=None, session=None, sessionName='AdminTask',
                 roleName = None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3.Session()
        self.get_caller_account()
        self.sessionName = self.session.client('sts').get_caller_identity().get('Arn').split('/')[-1]
        self.account_id = account_id 
        self.roleName = roleName if roleName else self.get_role_name()
        self.credentials = self.get_credentials() if self.roleName else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def get_caller_account(self):
        def _get_sso_profile(profile_name):
            """
            Gets the appropriate profile for SSO login, checking for source_profile.
            """
            config_path = os.path.expanduser('~/.aws/config')
            config = configparser.ConfigParser()
            config.read(config_path)
            
            section_name = f'profile {profile_name}' if profile_name != 'default' else 'default'
            
            if section_name in config and 'source_profile' in config[section_name]:
                return config[section_name]['source_profile']        
            return profile_name
            
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except Exception as e:
            if "expired" in str(e):
                loggin_profile = _get_sso_profile(self.session.profile_name)
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                os.system(f"aws sso login --profile {loggin_profile}")
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

    def client_config(self, service, region=None):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = region if region else self.region,
        )
    
    def get_role_name(self):
        user_input = input(f"What is the name of the role to be assumed? ({self.account_id}) ")
        if user_input:
            return user_input
        else:
            return None


def delimiter(symbol='='):
    logger.info(symbol * 120)

logger = logging.getLogger('Logging')