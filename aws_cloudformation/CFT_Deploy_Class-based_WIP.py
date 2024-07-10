import boto3
import json
import os
import logging
import uuid
from botocore.exceptions import ClientError


ASSUMED_ROLE = "AWSControlTowerExecution" 


class CloudFormation():
    def __init__(self, account_id, logger, mstr_session=None, 
                 role_name=ASSUMED_ROLE, region="us-west-2"):
        self.logger = logger
        self.accountid = account_id        
        self.rolename = role_name
        self.mstr_session = (mstr_session if mstr_session else 
                            boto3.session.Session())
        self.credentials = self.assume_role(self.mstr_session,self.accountid,
                                            "AccountMigrationTasks")
        self.session = boto3.session.Session(
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name=region
            )
        
    def assume_role(self,lcl_session,account_id,session_name,duration=900):
        response = lcl_session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.rolename}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self,creds,service,region='us-west-2'):
        response = boto3.session.Session().client(
            aws_access_key_id = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token = creds['SessionToken'],
            region_name = region,
            service_name = service
        )
        return response
    
    def wait_for_stack_update(self, waiter_function, stack_name, **kwargs):
        """
        Waits for the CloudFormation stack update to complete.

        Args:
            cloudformation (boto3.client): The CloudFormation client.
            stack_name (str): The name of the CloudFormation stack.

        Returns:
            None
        """
        # confiure cloudformation client
        cloudformation = self.client_config("cloudformation")
        print("Waiting for stack update to complete...")
        waiter = cloudformation.get_waiter(waiter_function)
        waiter_args = {
            "StackName": stack_name,
            "WaiterConfig": {
                "Delay": 5,
                "MaxAttempts": 60
            }
        }
        waiter_args.update(kwargs)
        waiter.wait(**waiter_args)
        print(f"Stack '{stack_name}' updated successfully.")

    def deploy_cloudformation_stack(self,stack_name,template):
        """
        Deploys a CloudFormation stack using the provided stack name.

        Args:
            stack_name (str): The name of the CloudFormation stack to be deployed.

        Returns:
            None
        """
        # Generate a unique change set name
        change_set_name = f"{stack_name[:9]}{uuid.uuid4().hex}"
        # Create the CloudFormation client
        cloudformation = self.client_config("cloudformation")
        # Create the change set
        print("Creating change set...")
        cloudformation.create_change_set(
            StackName=stack_name,
            TemplateBody=template,
            ChangeSetName=change_set_name,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )

        # Wait for the change set to be created
        print("Waiting for change set to be created...")
        self.wait_for_stack_update(
            "change_set_create_complete",
            stack_name=stack_name,
            ChangeSetName=change_set_name
        )
        # waiter = cloudformation.get_waiter("change_set_create_complete")
        # waiter.wait(
        #     StackName=stack_name,
        #     ChangeSetName=change_set_name,
        #     WaiterConfig={
        #         "Delay": 5,
        #         "MaxAttempts": 60,
        #     },
        # )
        print("Change set created.")

        # Execute the change set
        print("Executing change set...")
        cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
        )
        print("Change set executed.")

        # Wait for the stack update to complete
        self.wait_for_stack_update(
            "stack_update_complete",
            stack_name=stack_name
        )

        print(f"Stack '{stack_name}' deployed successfully.")


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


stack_name = input("Name of the Stack to deploy: ")
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
