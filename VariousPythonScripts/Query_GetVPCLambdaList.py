import boto3
import json
import os
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


appUd_sg_names = [
    'GetAppUpdater',
    'Proxy',
    'VersionCheck'
    'GetBinaries',
    'GetConfigs',
    'GetOthers',
    'UpdateComplete',
    'CheckStatus',
    'GetFramework',
    'FileZip',
    'FileCopy',
    'CombineResult',
    'Deploy',
    'Publish',
]

sg_names = [
    'ClientLoginAuthorizer',
    'UnzipConfigs'
]

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

    def get_functions(self):
        client = self.client_config('lambda')
        function_list = []
        vpc_functs = []
        paginator = client.get_paginator('list_functions')
        page_iterator = paginator.paginate()
        for page in page_iterator:
            function_list.extend([funct['FunctionName'] for funct in 
                                  page['Functions']])
            vpc_functs.extend([(funct['FunctionName'],funct['VpcConfig']) for funct in 
                               page['Functions'] if (funct.get('VpcConfig') and funct.get('VpcConfig').get('VpcId'))])
        self.all_functions = function_list
        self.vpc_functions = vpc_functs

        # for funct in client.list_functions()['Functions']:
        #     if funct.get('VpcConfig'):
        #         function_list.append(funct['FunctionName'])
        # self.vpc_functions = function_list



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

def name_generator(preferredName,prefix=None,suffix=None):
    return (prefix if prefix else "" ) + preferredName + (suffix if suffix else "")

logger = logging.getLogger('AWSLogging')
logger.setLevel(logging.INFO)
region = 'us-west-2'


session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
test_token(session)

dev_ceapp = Account(account_id="047787824797",session=session)
dev_ceapp.get_functions()
# print(dev_ceapp.all_functions)
print(len(dev_ceapp.all_functions))
print(dev_ceapp.vpc_functions)
print(len(dev_ceapp.vpc_functions))

# dev_ceapp.ec2 = dev_ceapp.client_config('ec2')
# for groupname in appUd_sg_names:
#     name = name_generator(groupname,'lambda-AppUpdater-','-DevA')
#     dev_ceapp.ec2.create_security_group(
#         Description=f'Controls access for {name }Lambda',
#         GroupName=name,
#         VpcId='vpc-02ab744df11bc6380',
#         DryRun=False
#     )
# for groupname in sg_names:
#     name = name_generator(preferredName=groupname,prefix='lambda-',suffix="-DevA")
#     dev_ceapp.ec2.create_security_group(
#         Description=f'Controls access for {name }Lambda',
#         GroupName=name,
#         VpcId='vpc-02ab744df11bc6380',
#         DryRun=False
#     )
