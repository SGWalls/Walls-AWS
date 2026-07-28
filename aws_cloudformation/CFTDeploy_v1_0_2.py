import boto3
import os
import logging
import uuid
import argparse
import re
import subprocess
import shlex
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import WaiterError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError



def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except Exception as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            cmd = f"aws sso login --profile {session.profile_name}"
            subprocess.run(shlex.split(cmd), check=True)
    return 

def sanitize_session_name(session_name):
    # Remove invalid characters
    clean_name = re.sub(r'[^a-zA-Z0-9=,.@-]', '-', session_name)
    
    # Truncate to 64 characters if needed
    if len(clean_name) > 64:
        clean_name = clean_name[:64]
    
    return clean_name

def get_session_name_from_sso_session(session):
    # Get the credentials from the session
    try:
        # Try to get the identity if available
        identity = session.client('sts').get_caller_identity()
        # Extract useful information from the ARN
        arn_parts = identity['Arn'].split('/')
        if len(arn_parts) > 1:
            return sanitize_session_name(arn_parts[-1])
    except Exception as e:
        print(f"Could not get identity: {e}")
    # Fallback: Create a session name using timestamp
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    return f"cloudformation_deploy-{timestamp}"

# function to validate AWS account id is correct format
def check_accountid_format(accountId):
    if not isinstance(accountId, str):
        raise TypeError("Account ID must be a string")
    if (len(accountId) == 12 and accountId.isdigit()):
        return True
    else:
        print("Account ID is INVALID!")
        return False
    
def get_sts_client(session=None):
    if session is None:
        session = boto3.Session()
    return session.client('sts')

def assume_role(account_id, session, duration=900 ):
    session_name = get_session_name_from_sso_session(session)
    if not check_accountid_format(account_id):
        raise ValueError("Invalid account_id format")
    sts = get_sts_client(session)
    try:
        response = sts.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/AWSControlTowerExecution',
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']
    except ClientError as e:
        logger.error(f"Error assuming role: {e}")
        raise

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


if __name__ == "__main__":        
    parser = argparse.ArgumentParser(description="Deploy the referenced cloudformation Template to the target account.")
    parser.add_argument('-s', '--stack_name', type=str, help="Name of the stack to deploy")
    parser.add_argument('-d', '--directory', type=str, help="Directory path of the target file")
    parser.add_argument('-f', '--file', type=str, help="Name of the target template file")
    parser.add_argument('-t', '--target', type=str, help="Account ID of the target account")
    args = parser.parse_args()

    stack_name = args.stack_name
    file_directory = args.directory
    file_name = args.file
    target_input = args.target

    # stack_name = input("Name of the Stack to deploy: ")
    # file_directory = input("what is the Directory Path of the target file? ")
    # file_name = input("What is the name of the target template file? ")
    # target_input = input("List the Account IDs for the target account " 
    #                     "(Separate multiple entries with a comma ','): ")
    # new_parameters = input("Define the parameters for new stack creation: ")
    accounts = target_input.split(',')
    directory = os.path.normpath(file_directory)
    file = file_name
    filepath = os.path.join(directory,file)
    with open(filepath, 'rt') as f:
        template = f.read()
    stack_params = {
        'StackName': stack_name,
        'TemplateBody': template,
        'Capabilities': [
            'CAPABILITY_NAMED_IAM'
        ]
    }
    # if new_parameters:
    #     new_parameters = new_parameters.split(',')
    # # set new_parameters to a list of dictionaries
    #     new_parameters = [{'ParameterKey': param.split('=')[0],
    #                     'ParameterValue': param.split('=')[1]}
    #                     for param in new_parameters]
    #     # print(new_parameters)
    #     stack_params['Parameters'] = new_parameters
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
        credentials = assume_role(account,session=session)
        cloudformation = client_config(credentials,"cloudformation")
        try:
            stack_map = {stack['StackName'].lower():stack['StackName'] for stack in cloudformation.list_stacks()['StackSummaries']}
            if stack_name.lower() in stack_map.keys():
                stack_name = stack_map[stack_name.lower()]
            existing_stack = cloudformation.describe_stacks(
                StackName=stack_name
            )['Stacks'][0]
            # cloudformation.describe_stacks(StackName=stack_name)
            # cloudformation.create_stack(**stack_params)
            # print(f"Stack Deployed to account {account}")
        # catch validation error   
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError':
                print(f"Stack {stack_name} does not exist in account {account}. "
                    "Creating stack.")
                new_parameters = input("Define the parameters for new stack creation: ")
                if new_parameters:
                    new_parameters = new_parameters.split(',')
                # set new_parameters to a list of dictionaries
                    new_parameters = [{'ParameterKey': param.split('=')[0],
                                    'ParameterValue': param.split('=')[1]}
                                    for param in new_parameters]
                    # print(new_parameters)
                    stack_params['Parameters'] = new_parameters
                cloudformation.create_stack(**stack_params)
                print(f"Stack Deployed to account {account}")
        # except ClientError as e:
        #     if e.response['Error']['Code'] == 'AlreadyExistsException':
        #         print(f"Stack {stack_name} already exists in account {account}. "
        #             "Creating a Change Set for the stack.")
        #         # turn lines 105 - 139 in to a function
        else:            
            changeSetName = f"{stack_name[:9]}{uuid.uuid4().hex}"
            chg_parameters = input("New Parameters for Change? (ParameterName=Value): ")

             # Get existing parameters from the stack
            existing_parameters = {param['ParameterKey']: param['ParameterValue'] 
                                for param in existing_stack.get('Parameters', [])}
            if chg_parameters:
                chg_parameters = chg_parameters.split(',')
                new_params = {param.split('=')[0]: param.split('=')[1] 
                                 for param in chg_parameters}

                final_parameters = []
                for key, value in existing_parameters.items():
                    if key in new_params:
                        final_parameters.append({
                            'ParameterKey': key,
                            'ParameterValue': new_params[key]
                        })
                    else:
                        final_parameters.append({
                            'ParameterKey': key,
                            'ParameterValue': value
                        })                                
            else:
                final_parameters = existing_stack['Parameters'] if existing_stack.get('Parameters') else list()
            cloudformation.create_change_set(
                StackName=stack_name,
                TemplateBody=template,
                ChangeSetName=changeSetName,
                Parameters=final_parameters,
                Capabilities=[
                    'CAPABILITY_NAMED_IAM'
                ]
            )
            print("Created Change Set.  Waiting. . .")
            waiter = cloudformation.get_waiter('change_set_create_complete')
            try:
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
            except WaiterError as e:
                response = cloudformation.describe_change_set(
                    ChangeSetName=changeSetName,
                    StackName=stack_name
                )
                if (response['Status'] == 'FAILED' and 
                    "The submitted information didn't contain changes" in response['StatusReason']):
                    print("No changes to deploy - continuing...")
                    continue
                else:
                    # If it failed for any other reason, raise the exception
                    raise e    
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
 