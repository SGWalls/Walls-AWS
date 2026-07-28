"""AWS SSO Access Delegation Report Generator

Generates an Excel report of AWS IAM Identity Center (SSO) access delegations,
showing which groups have access to which accounts via which permission sets.

Requirements:
    - boto3, pandas, xlsxwriter
    - AWS profile 'ct_master' configured with SSO access
    - retriever module with validate_sso_token function

Output:
    Excel file in Documents/AWS_Projects/exports/AWS-IAM-IDC-AccessDelegations/
"""

import boto3
import csv
import os
import pandas as pd
from retriever import validate_sso_token
from datetime import datetime

# Set up output directory in user's Documents folder
userprofile = os.environ["USERPROFILE"]
file_location = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\exports\\AWS-IAM-IDC-AccessDelegations\\"
    )
if not os.path.exists(file_location):
    os.makedirs(file_location)

# Store all assignment data for the report
data = []


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

print(f"Excel report has been generated: {output_file}")