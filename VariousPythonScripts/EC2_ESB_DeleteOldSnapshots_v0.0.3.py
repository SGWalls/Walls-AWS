import boto3
import datetime
from datetime import datetime
import logging
import os
import sys
from helpers.Account import Account
print(os.getcwd())

ASSUMED_ROLE = "AWSControlTowerExecution" 


# class Account():
#     def __init__(
#             self, account_id, logger, role_name=ASSUMED_ROLE,
#             region="us-west-2"):
#         self.logger = logger
#         self.accountid = account_id        
#         self.rolename = role_name
#         self.session = boto3.session.Session(
#             aws_access_key_id = self.credentials['AccessKeyId'],
#             aws_secret_access_key = self.credentials['SecretAccessKey'],
#             aws_session_token = self.credentials['SessionToken'],
#             region_name=region
#         )
#         self.credentials = self.assume_role(self.accountid,
#                                             "EBSSnapshotManagement")
        

#     def assume_role(self,account_id,session_name,duration=900):
#         response = self.session.client("sts").assume_role(
#             RoleArn=f"arn:aws:iam::{account_id}:role/{self.rolename}",
#             RoleSessionName=session_name,
#             DurationSeconds=duration
#         )
#         return response['Credentials']
    
#     def client_config(self,creds,service,region="us-west-2"):
#         response = boto3.session.Session().client(
#             aws_access_key_id = creds['AccessKeyId'],
#             aws_secret_access_key = creds['SecretAccessKey'],
#             aws_session_token = creds['SessionToken'],
#             region_name = region,
#             service_name = service
#         )
#         return response


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


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
        "logging\\EBSSnapShotMaintenance\\"
)
log_file_name = f"EBSSnapshotMaintenance-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

logger = create_logger('EBSSnapshotLogger',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
Aws_Account = Account('059004262227',logger)
# session = boto3.Session(profile_name='dev_devops',region_name='us-west-2')
# ec2 = session.client('ec2')

paginator = Aws_Account.client_config('ec2').get_paginator('describe_snapshots')
page_iterator = paginator.paginate(
    OwnerIds=[
        'self'
        ]
)
in_scope_snaps = []
for page in page_iterator:
    for snapshot in page['Snapshots']:
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if (current_time - snapshot['StartTime']).days > 60:
            in_scope_snaps.append(snapshot)
len(in_scope_snaps)