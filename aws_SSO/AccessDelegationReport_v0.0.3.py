"""AWS SSO Access Delegation Report Generator

Generates an Excel report of AWS IAM Identity Center (SSO) access delegations,
showing which groups have access to which accounts via which permission sets.

Requirements:
    - boto3, pandas, xlsxwriter

Output:
    Excel file in Documents/AWS_Projects/exports/AWS-IAM-IDC-AccessDelegations/
"""

"""
!!!DISCLAIMER!!!: This script is provided "as-is" without warranty of any kind.
The executor assumes full responsibility for any errors encountered during
execution and any modifications required for proper functionality.
Use at your own risk.
"""

import boto3
import botocore
import configparser
import logging
import os
import subprocess
import shlex
import pandas as pd
from configparser import ConfigParser
from datetime import datetime

# Set up output directory in user's Documents folder
userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"
file_location = os.path.dirname(
        f"{userprofile}\\Documents\\exports\\AWS-IAM-IDC-AccessDelegations\\"
    )
if not os.path.exists(file_location):
    os.makedirs(file_location)

# Set Profile Name and Role Name for named profile in config file
profileName = 'idc_admin'
profileRoleName = 'ITOps_IdentityCenterAdmin'
profileAccountId = '016873650354'

# Store all assignment data for the report
data = []

def delimiter(symbol='='):
    logger.info(symbol * 120)

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

def validate_sso_token(session):
    """
    Validates if the AWS SSO token for a given session is still valid.
    Triggers login if token is expired or invalid.
    Args:
        session (str): The session object to validate
    Returns:
        bool: True if valid session established, False otherwise
    """
    def _get_sso_profile(profile_name):
        """
        Gets the appropriate profile for SSO login, checking for source_profile.
        """
        config_path = os.path.expanduser('~/.aws/config')
        config = configparser.ConfigParser()
        config.read(config_path)
        
        section_name = f'profile {profile_name}' if profile_name != 'default' else 'default'
        
        if section_name in config and 'source_profile' in config[section_name]:
            return config[section_name]['source_profile']
        
        return profile_name
        
    try:
        # Try to create a session with the profile
        sts = session.client('sts')
        # Test the credentials by making a simple API call
        sts.get_caller_identity()
        return True
    except (botocore.exceptions.TokenRetrievalError,
            botocore.exceptions.UnauthorizedSSOTokenError) as e:
        logger.info(e)
        
        # Get the profile to use for SSO login
        login_profile = _get_sso_profile(session.profile_name)
        
        logger.info(f"SSO token for profile {login_profile} is expired or invalid. Initiating login...")
        try:
            subprocess.run(shlex.split(f"aws sso login --profile {login_profile}"))
            return True
        except subprocess.CalledProcessError as sso_error:
            logger.info(f"Failed to login with SSO: {sso_error}")
            return False
    except Exception as e:
        logger.info(e)
        return False

def awscliv2_exists():
    # Return True if AWSCLIv2 is installed
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )

def is_aws_cli_installed():
    """
    Checks if the AWS CLI is installed and in the system's PATH.

    Returns:
        bool: True if AWS CLI is installed, False otherwise.
        str: The version string if installed, or an error message if not.
    """
    try:
        # Run the 'aws --version' command
        # use shell=True for this command to work correctly across all OSes
        result = subprocess.run(['aws', '--version'], capture_output=True, text=True, check=True, shell=True)
        # If the command succeeds, it typically logger.infos to stderr (strangely for version info)
        version_output = result.stderr.strip() if result.stderr else result.stdout.strip()
        return True, version_output
    except subprocess.CalledProcessError as e:
        # The command failed (e.g., 'command not found')
        return False, f"Command failed: {e.stderr.strip() if e.stderr else e.stdout.strip()}"
    except FileNotFoundError:
        # The 'aws' executable was not found in the system's PATH
        return False, "The 'aws' command was not found. AWS CLI is likely not installed or not in PATH."
    except Exception as e:
        # Handle other potential errors
        return False, f"An unexpected error occurred: {e}"

def append_profiles(filepath, account_id, account_name, role_name, filetype="config"):
    delimiter()
    logger.info("Adding profile to your aws config file")
    config = ConfigParser()
    config.read(filepath)
    if filetype.lower() == "config":
        profile = "profile "
    if filetype.lower() == "credentials":
        profile = ""
    config[f"{profile}{account_name}"] = dict(
        sso_session = 'glb_session',
        sso_account_id = account_id,
        sso_role_name = role_name,
        region = region,
        output = "json",
    )
    config["sso-session glb_session"] = dict(
        sso_start_url = "https://globeaws.awsapps.com/start",
        sso_region = region,
        sso_registration_scopes = "sso:account:access"
    )
    
    with open(filepath, "w") as configfile:
        config.write(configfile)
    
    delimiter()
    logger.info(f"Added profile {profile}{account_name} to your aws config file")

def get_sso_instance_list():
    """Retrieve all SSO instances in the organization."""
    paginator = sso.get_paginator('list_instances')
    for page in paginator.paginate():
        for instance in page['Instances']:
            yield instance

def get_permission_set_list(instance_arn):
    """Retrieve all permission sets for a given SSO instance."""
    paginator = sso.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set in page['PermissionSets']:
            yield permission_set

def build_permission_set_dict(instance_arn):
    """Build a dictionary mapping permission set ARNs to their names."""
    permission_set_dict = {}
    for permission_set in get_permission_set_list(instance_arn):
        permission_set_details = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set)
        permission_set_dict[permission_set] = permission_set_details['PermissionSet']['Name']
    return permission_set_dict

def get_permission_set_name(instance_arn, permission_set_arn):
    """Get the friendly name for a permission set ARN."""
    permission_set_details = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
    return permission_set_details['PermissionSet']['Name']

def get_group_list(identity_store_id):
    """Retrieve all groups from the Identity Store."""
    paginator = identity_store.get_paginator('list_groups')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for group in page['Groups']:
            yield group

def get_assignments_for_principal(principal_id, principal_type, instance_arn):
    """Get all account assignments for a specific principal (group or user)."""
    paginator = sso.get_paginator('list_account_assignments_for_principal')
    for page in paginator.paginate(PrincipalId=principal_id, PrincipalType=principal_type,InstanceArn=instance_arn):
        for assignment in page['AccountAssignments']:
            yield assignment

def get_account_list():
    """Retrieve all AWS accounts in the organization."""
    paginator = org.get_paginator('list_accounts')
    for page in paginator.paginate():
        for account in page['Accounts']:
            yield account

def build_account_dict():
    """Build a dictionary mapping account IDs to account names."""
    account_dict = {}
    for account in get_account_list():
        account_dict[account['Id']] = account['Name']
    # Add external account mapping
    account_dict['662627786878'] = 'Globe Life'
    return account_dict


# Create logger object for this module
log_path = f"{file_location}\\logging\\"
log_file_name = f"AccessDelegationReport_{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
logger = create_logger(
    logger_name = __name__,
    log_path = log_path,
    log_file_name = log_file_name
    )

# Check if AWS CLI v2 is installed and add profile to config if it is
installed, message = is_aws_cli_installed()
if installed:
    logger.info(f"AWS CLI is installed. Version information: {message}")
    append_profiles(
        aws_config_file,
        profileAccountId,
        profileName,
        profileRoleName
    )
else:
    logger.info(f"AWS CLI is not installed: {message}")
    raise SystemExit()

# Initialize AWS session and clients
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)  # Ensure SSO token is valid
sso = session.client('sso-admin')
identity_store = session.client('identitystore')
org = session.client('organizations')

# Build lookup dictionaries for account names
account_dict = build_account_dict()

# Get SSO instance details
instance_list = get_sso_instance_list()
for instance in instance_list:
    instance_details = instance

# Get all groups from Identity Store
identity_store_id = instance_details['IdentityStoreId']
group_list = get_group_list(identity_store_id)

# Cache permission set names to reduce API calls
permission_set_dict = {}
    
# Iterate through all groups and collect their assignments
for group in group_list:
    group_details = group
    group_id = group_details['GroupId']
    group_name = group_details['DisplayName']
    assignments = get_assignments_for_principal(group_id, 'GROUP', instance_details['InstanceArn'])
    
    # Process each assignment for the group
    for assignment in assignments:
        # Cache permission set name to avoid repeated API calls
        if not permission_set_dict.get(assignment['PermissionSetArn']):
            permission_set_dict[assignment['PermissionSetArn']] = get_permission_set_name(
                instance_details['InstanceArn'], 
                assignment['PermissionSetArn']
            )
        
        # Add assignment details to report data
        data.append({
            'Group': group_name,
            'PermissionSet': permission_set_dict[assignment['PermissionSetArn']],
            'AccountId': assignment['AccountId'],
            'AccountName': account_dict[assignment['AccountId']]
        })

# Convert collected data to DataFrame
df = pd.DataFrame(data)

# Generate timestamped output filename
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = os.path.join(file_location, f'AWS-IAM-IDC-AccessDelegations_{timestamp}.xlsx')

# Create formatted Excel report
with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
    # Write DataFrame to Excel
    df.to_excel(writer, sheet_name='SSO Assignments', index=False)
    
    # Get workbook and worksheet objects to apply formatting
    workbook = writer.book
    worksheet = writer.sheets['SSO Assignments']
    
    # Define header formatting (bold, gray background, border)
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#D3D3D3',
        'border': 1
    })
    
    # Apply formatting to header row
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(0, col_num, value, header_format)
    
    # Auto-adjust column widths based on content
    for idx, col in enumerate(df.columns):
        max_length = max(
            df[col].astype(str).apply(len).max(),
            len(col)
        )
        worksheet.set_column(idx, idx, max_length + 2)

logger.info(f"Excel report has been generated: {output_file}")