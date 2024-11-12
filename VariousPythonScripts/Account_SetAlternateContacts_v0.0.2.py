import boto3
import json
import subprocess, shlex
import os
import logging 
from datetime import datetime
import botocore
import sys
from retriever import validate_sso_token

# script_dir = os.path.dirname(__file__)
# module_dir = os.path.join(script_dir, '..')
# sys.path.append(module_dir)
# from helpers.helper import validate_sso_token

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\UpdateAWSAccountPWPolicy\\"
    )
log_file_name = f"account-updateAltContact-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


# def validate_sso_token(session):
#     """
#     Validates if the AWS SSO token for a given session is still valid.
#     Triggers login if token is expired or invalid.
    
#     Args:
#         session (str): The session object to validate
    
#     Returns:
#         bool: True if valid session established, False otherwise
#     """
#     try:
#         # Try to create a session with the profile
#         sts = session.client('sts')
        
#         # Test the credentials by making a simple API call
#         sts.get_caller_identity()
#         return True
#     except botocore.exceptions.TokenRetrievalError as e:
#         logger.info(e)
#         logger.info(f"SSO token for profile {session.profile_name} is expired or invalid. Initiating login...")
#         try:
#             # Run the SSO login command
#             # subprocess.run(['aws', 'sso', 'login', '--profile', profile_name], check=True)
#             subprocess.run(shlex.split(
#                 f"aws sso login --profile {session.profile_name}"
#             ))
#             return True
#         except subprocess.CalledProcessError as sso_error:
#             logger.info(f"Failed to login with SSO: {sso_error}")
#             return False

def get_accounts(session):
    client = session.client('organizations')
    validate_sso_token(session)
    accounts = []
    response = client.list_accounts()
    accounts.extend([account for account in response['Accounts'] if account['Status'] == 'ACTIVE'])
    while 'NextToken' in response:
        response = client.list_accounts(NextToken=response['NextToken'])
        accounts.extend([account for account in response['Accounts'] if account['Status'] == 'ACTIVE'])
    return accounts

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

logger = create_logger('Logging',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master')
validate_sso_token(session)
account_client = session.client('account')

account_list = get_accounts(session)
for account in account_list:
    account_id = account['Id']
    if not account_client.get_alternate_contact(
        AccountId=account_id,
        AlternateContactType='SECURITY'
    )['AlternateContact']:
        logger.info(f"Updating alternate contact for account {account_id}")
        try:
            account_client.put_alternate_contact(
                AccountId=account_id,
                AlternateContactType='SECURITY',
                EmailAddress='AWSSecurityNotifications@Globe.Life',
                PhoneNumber='469-617-4431',
                Name='Globe Life Security Notifications',
                Title='IT Security'
            )
        except Exception as e:
            logger.info(f"Error updating alternate contact for account {account_id}: {e}")
            continue
    else:
        logger.info(f"Alternate contact already exists for account {account_id}")
    
