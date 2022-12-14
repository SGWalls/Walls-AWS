import boto3
import os
import time
import json
import logging
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


def delimiter(symbol='='):
    print(symbol * 120)

logger = logging.getLogger('PublicAccessBlockEnabler_Logger')

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



def lambda_handler(event, context):
    try:
        account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]
    except KeyError:
        print(f"Unable to get an account Id from this event: {event}")
        return
