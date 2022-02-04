#!/bin/sh

import boto3
import json
import os
import logging
import pprint
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from configparser import ConfigParser

logger = logging.getLogger()
logger.setLevel(logging.INFO)

userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"

def awscliv2_exists():
    "Return True if AWSCLIv2 is installed"
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )


def append_profiles(filepath, account_id, account_name, role_name, filetype="config"):
    delimiter()
    print("Adding profile to your aws config file")
    config = ConfigParser()
    config.read(filepath)
    if filetype.lower() == "config":
        profile = "profile "
    if filetype.lower() == "credentials":
        profile = ""
    config[f"{profile}{account_name}"] = dict(
        sso_start_url = "https://globeaws.awsapps.com/start",
        sso_region = region,
        sso_account_id = account_id,
        sso_role_name = role_name,
        region = region,
        ca_bundle = "C:\\Program Files\\Amazon\\AWSCLIV2\\nskp_config\\netskope-cert-bundle.pem",
        output = "json",
    )
    
    with open(filepath, "w") as configfile:
        config.write(configfile)
    
    delimiter()
    print(f"Added profile {profile}{account_name} to your aws config file")


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


def check_input(inpt: str):
    if inpt:
        return True
    else:
        print("Input is empty!")
        return False


def check_format(accountId):
    if (len(accountId) == 12 and accountId.isdigit()):
        return True
    else:
        print("Account ID is INVALID!")
        return False


def delimiter(symbol='='):
    logger.info(symbol * 120)


########## TO DO ############
##[X] Cross Account access ##
##[ ] Define Functions #####

while True: 
    account_id = input("Enter the AWS Account ID of the Account where the error occurred: ")
    if not check_input(account_id):
        continue
    elif not check_format(account_id):
        continue
    else:
        break
# encoded_message = input("Enter the Encoded Message: ")
target_account_name = input("Enter the of the Target Account: ")
target_account_name = target_account_name.replace(" ","_").lower()
role_name = input(
    "Name of the role you use for accessing the account (Case Sensitive):  "
)

print("Enter the Encoded Message: ")
encoded_message = []
while True:
    try:
        line = input()
        if not line:
            break
    except EOFError:
        break
    encoded_message.append(line)
encoded_message = ''.join((''.join(encoded_message)).split())

if awscliv2_exists:
    append_profiles(aws_config_file,account_id,target_account_name,role_name)
session = boto3.session.Session(
    profile_name=target_account_name,
    region_name=region
)
test_token(session)
sts = session.client('sts')


response = sts.decode_authorization_message(EncodedMessage=encoded_message)
response_dict = json.loads(response["DecodedMessage"])

pprint.pprint(response_dict)
