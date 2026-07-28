import boto3
import botocore
import csv
import subprocess, shlex
import logging
from datetime import datetime


SESSION = boto3.Session(profile_name='ct_master',region_name='us-west-2')
logger = logging.getLogger(__name__)
org_map = {
    'o-k3vox4srr1':'GMAD-LA',
    'o-w3wk3dircz':'Globe Enterprise',
    'o-tuwjxnhqr4':'Globe Legacy'
}

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
            botocore.exceptions.UnauthorizedSSOTokenError,
            botocore.exceptions.SSOTokenLoadError) as e:
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

def get_all_accounts():
    """Retrieve all accounts from AWS Organizations"""
    org_client = SESSION.client('organizations')
    accounts = []
    
    # Handle pagination
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    
    return accounts

def get_root_id(session):
    org_client = session.client('organizations')
    root_id = org_client.list_roots()['Roots'][0]['Id']
    return root_id

def get_org_id(session):
    org_client = session.client('organizations')
    org_id = org_client.describe_organization()['Organization']['Id']
    return org_id

def write_accounts_to_csv(accounts):
    """Write account information to CSV file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports'
    filename = f'aws_account_list{timestamp}.csv'
    filename = f'{file_path}\\{filename}'
    org_id = get_org_id(SESSION)
    org_name = org_map[org_id]
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['Org ID','Org Name','Account ID', 'Account Name', 'Email', 'Status'])
        
        # Write account data
        for account in accounts:
            writer.writerow([
                org_id,
                org_name,
                account['Id'],
                account['Name'],
                account['Email'],
                account['Status']
            ])
    
    return filename

def main():
    validate_sso_token(SESSION)
    try:
        # Get all accounts
        accounts = get_all_accounts()
        
        # Write to CSV
        output_file = write_accounts_to_csv(accounts)
        print(f"Successfully wrote account information to {output_file}")
        print(f"Total accounts processed: {len(accounts)}")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
