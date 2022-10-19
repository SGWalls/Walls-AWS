import boto3
import json
import os
import logging
import time
import secrets
import string
import random
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


session = boto3.Session(profile_name='id_svcs',region_name='us-west-2')
cognito = session.client('cognito-idp')

def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session):
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

userPoolId = input('Enter the User Pool ID: ')
logger = logging.getLogger()
user_list = []
paginator = cognito.get_paginator('list_users')
iterator = paginator.paginate(UserPoolId=userPoolId,Filter="cognito:user_status=\"FORCE_CHANGE_PASSWORD\"")
for page in iterator:
    user_list.extend(page['Users'])
#  user_list = cognito.list_users(UserPoolId='us-west-2_56Gs8AXbz')

username_list = []
for name in user_list:
    username_list.append(name['Username'])

for user in username_list:
    cognito.admin_set_user_password(UserPoolId=userPoolId,Username=user,
        Password=''.join((secrets.choice(string.ascii_letters + string.digits + 
            string.punctuation) for i in range(256))) ,Permanent=True)
def get_string(letters_count, digits_count):
    letters = ''.join((random.choice(string.ascii_letters) for i in range(letters_count)))
    digits = ''.join((random.choice(string.digits) for i in range(digits_count)))
    # Convert resultant string to list and shuffle it to mix letters and digits
    sample_list = list(letters + digits)
    random.shuffle(sample_list)
    # convert list to string
    final_string = ''.join(sample_list)
    return final_string