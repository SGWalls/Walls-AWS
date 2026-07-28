import boto3
import logging
import os
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

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
        return self.assume_role('ssm_SetPublicAccessBlock') if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, 
                    role_name="aws-controltower-AdministratorExecutionRole", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service, region):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = region,
        )


region_list = ['us-west-2','us-west-1','us-east-1','us-east-2']
session = boto3.Session(region_name='us-west-2')

def delimiter(symbol='='):
    logger.info(symbol * 120)


logger = logging.getLogger('ssm_SetPublicAccessBlock')
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']


def lambda_handler(event, context):
    print(event)
    try:
        account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]
    except KeyError:
        print(f"Unable to get an account Id from this event: {event}")
        return
    target_account = Account(account_id=account_id,region=region)

    for region_itr in region_list:
        ssm = target_account.client_config('ssm',region=region_itr)
        response = ssm.get_service_setting(SettingId='/ssm/documents/console/public-sharing-permission')
        if response['ServiceSetting']['SettingValue'] == 'Enable':
            try:
                logger.info(f'Enabling public access block for SSM documents in account {target_account.account_id} for region {region_itr}')
                response = ssm.update_service_setting(
                    SettingId='/ssm/documents/console/public-sharing-permission',
                    SettingValue='Disable'
                )
                logger.info(response)
                logger.info(f'-=[ {region_itr} ]=---=Public Block Enabled=--')
            except Exception as e: 
                logger.info(e)
        else: 
            logger.info(f'!! Public Block already enabled for Account: {target_account.account_id}, in Region: {region_itr}')
