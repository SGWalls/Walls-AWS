import subprocess, shlex
import logging 
import botocore
import os

logger = logging.getLogger(__name__)

def validate_sso_token(session):
    """
    Validates if the AWS SSO token for a given session is still valid.
    Triggers login if token is expired or invalid.
    
    Args:
        session (str): The session object to validate
    
    Returns:
        bool: True if valid session established, False otherwise
    """
    try:
        # Try to create a session with the profile
        sts = session.client('sts')
        
        # Test the credentials by making a simple API call
        sts.get_caller_identity()
        return True
    except (botocore.exceptions.TokenRetrievalError, 
            botocore.exceptions.UnauthorizedSSOTokenError) as e:
        logger.info(e)
        logger.info(f"SSO token for profile {session.profile_name} is expired or invalid. Initiating login...")
        try:
            # Run the SSO login command
            # subprocess.run(['aws', 'sso', 'login', '--profile', profile_name], check=True)
            subprocess.run(shlex.split(
                f"aws sso login --profile {session.profile_name}"
            ))
            return True
        except subprocess.CalledProcessError as sso_error:
            logger.info(f"Failed to login with SSO: {sso_error}")
            return False
    except Exception as e:
        logger.info(e)

def get_accounts_with_filter(session, root_identifier, parent_filter):
    org = session.client('organizations')
    target_ou_id_list = [
        ou['Id'] for ou in org.list_organizational_units_for_parent(
            ParentId=root_identifier)['OrganizationalUnits']
        if ou['Name'] in parent_filter
    ]
    target_account_list = []
    paginator = org.get_paginator('list_accounts_for_parent')
    for ou_id in target_ou_id_list:
        page_iterator = paginator.paginate(ParentId=ou_id)
        for page in page_iterator:
            target_account_list.extend([account for account in page['Accounts'] if account['Status'] == 'ACTIVE'])
    return target_account_list

def get_org_account_list(session,filter=None):
    client = session.client('organizations')
    if filter:
        accounts = get_accounts_with_filter(session,root_identifier=session.client('organizations').list_roots()['Roots'][0]['Id'],parent_filter=filter)
    else:
        validate_sso_token(session)
        accounts = []
        response = client.list_accounts()
        accounts.extend([account for account in response['Accounts'] if account['Status'] == 'ACTIVE'])
        while 'NextToken' in response:
            response = client.list_accounts(NextToken=response['NextToken'])
            accounts.extend([account for account in response['Accounts'] if account['Status'] == 'ACTIVE'])
    return accounts

def create_logger(logger_name, log_path, log_file_name):
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