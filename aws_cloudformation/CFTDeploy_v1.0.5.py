import boto3
import json
import os
import logging
import uuid
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


stack_name = input("Name of the Stack to deploy: ")


def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except Exception as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def assume_role(account_id, session_name, duration=900):        
    response = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/AWSControlTowerExecution",
        RoleSessionName=session_name,
        DurationSeconds=duration
    )
    return response['Credentials']


def client_config(creds,service,region='us-west-2'):
    response = session.client(
        aws_access_key_id = creds['AccessKeyId'],
        aws_secret_access_key = creds['SecretAccessKey'],
        aws_session_token = creds['SessionToken'],
        region_name = region,
        service_name = service
    )
    return response


def check_input(inpt: str):
    if inpt:
        inpt.split(',')
    else:
        print("Input is empty!")


def check_format(accountId):
    if (len(accountId) == 12 and accountId.isdigit()):
        return True
    else:
        print("Account ID is INVALID!")
        return False


def delimiter(symbol='='):
    logger.info(symbol * 120)


file_directory = input("what is the Directory Path of the target file? ")
file_name = input("What is the name of the target template file? ")
target_input = input("List the Account IDs for the target account " 
                    "(Separate multiple entries with a comma ','): ")

accounts = target_input.split(',')
directory = os.path.normpath(file_directory)
file = file_name
filepath = os.path.join(directory,file)
with open(filepath, 'rt') as f:
    template = f.read()

logger = logging.getLogger()
session = boto3.session.Session(
    profile_name="ct_master",
    region_name="us-west-2"
    )
sts = session.client('sts')
test_token(session)

for account in accounts:
    if not check_format(account):
        continue
    credentials = assume_role(account,"cloudFormationDeploy")
    cloudformation = client_config(credentials,"cloudformation")
    try:
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ]
        )
        print(f"Stack Deployed to account {account}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AlreadyExistsException':
            print(f"Stack {stack_name} already exists in account {account}. "
                  "Creating a Change Set for the stack.")
            # turn lines 105 - 139 in to a function
                
            changeSetName = f"{stack_name[:9]}{uuid.uuid4().hex}"
            cloudformation.create_change_set(
                StackName=stack_name,
                TemplateBody=template,
                ChangeSetName=changeSetName,
                Capabilities=[
                    'CAPABILITY_NAMED_IAM'
                ]
            )
            print("Created Change Set.  Waiting. . .")
            waiter = cloudformation.get_waiter('change_set_create_complete')
            waiter.wait(
                StackName=stack_name,
                ChangeSetName=changeSetName,
                WaiterConfig={
                    'Delay': 5,
                    'MaxAttempts': 60
                }
            )
            print("Change Set Created.  Executing Change Set. . .")
            cloudformation.execute_change_set(
                StackName=stack_name,
                ChangeSetName=changeSetName
            )
            print("Change Set Executed.")
            waiter = cloudformation.get_waiter('stack_update_complete')
            print("Waiting for Stack to be Updated. . .")
            waiter.wait(
                StackName=stack_name,
                WaiterConfig={
                    'Delay': 5,
                    'MaxAttempts': 60
                }
            )
            print(f"Stack Deployed to account {account}")
    except:
        raise
    # print(f"deployed stack to account {account}")
