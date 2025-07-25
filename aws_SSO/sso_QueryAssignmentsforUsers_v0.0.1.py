import boto3
import csv
import os
import pandas as pd
from retriever import validate_sso_token
from datetime import datetime


userprofile = os.environ["USERPROFILE"]
file_location = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\exports\\AWS-IAM-IDC-UserAccessDelegations\\"
    )
if not os.path.exists(file_location):
    os.makedirs(file_location)

data = []


def get_sso_instance_list():
    paginator = sso.get_paginator('list_instances')
    for page in paginator.paginate():
        for instance in page['Instances']:
            yield instance

def get_permission_set_list(instance_arn):
    paginator = sso.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set in page['PermissionSets']:
            yield permission_set

def build_permission_set_dict(instance_arn):
    permission_set_dict = {}
    for permission_set in get_permission_set_list(instance_arn):
        permission_set_details = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set)
        permission_set_dict[permission_set] = permission_set_details['PermissionSet']['Name']
    return permission_set_dict

def get_permission_set_name(instance_arn, permission_set_arn):
    permission_set_details = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
    return permission_set_details['PermissionSet']['Name']

def get_user_name(instanace_arn, principal_id):
    try:
        user_details = identity_store.describe_user(UserId=principal_id, IdentityStoreId=instanace_arn)
    except identity_store.exceptions.ResourceNotFoundException:
        user_details = {'UserName': 'Not Found'}
    return user_details['UserName']

def get_group_list(identity_store_id):
    paginator = identity_store.get_paginator('list_groups')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for group in page['Groups']:
            yield group

def get_assignments_for_principal(principal_id, principal_type, instance_arn):
    paginator = sso.get_paginator('list_account_assignments_for_principal')
    for page in paginator.paginate(PrincipalId=principal_id, PrincipalType=principal_type,InstanceArn=instance_arn):
        for assignment in page['AccountAssignments']:
            yield assignment

def get_account_list():
    paginator = org.get_paginator('list_accounts')
    for page in paginator.paginate():
        for account in page['Accounts']:
            yield account

def build_account_dict():
    account_dict = {}
    for account in get_account_list():
        account_dict[account['Id']] = account['Name']
    account_dict['662627786878'] = 'Globe Life'
    return account_dict
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)
sso = session.client('sso-admin')
identity_store = session.client('identitystore')
org = session.client('organizations')
account_dict = build_account_dict()
instance_list = get_sso_instance_list()
for instance in instance_list:
    instance_details = instance

for account in account_dict:
    permissions_set_list = sso.list_permission_sets_provisioned_to_account(AccountId=account, InstanceArn=instance_details['InstanceArn'])
    for permission_set in permissions_set_list['PermissionSets']:
        assignments = sso.list_account_assignments(AccountId=account, InstanceArn=instance_details['InstanceArn'],PermissionSetArn=permission_set)['AccountAssignments']
        for assignment in assignments:
            permission_set_name = get_permission_set_name(instance_details['InstanceArn'], assignment['PermissionSetArn'])
            principal_id = assignment['PrincipalId']
            principal_type = assignment['PrincipalType']
            account_name = account_dict[account]
            if principal_type == 'USER':
                data.append({
                    'Account': account_name,
                    'PermissionSet': permission_set_name,
                    'PermissionSetArn': assignment['PermissionSetArn'],
                    'PrincipalName': get_user_name(instance_details['IdentityStoreId'], principal_id),
                    'PrincipalId': principal_id,
                    'PrincipalType': principal_type
                })

df = pd.DataFrame(data)      

timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = os.path.join(file_location, f'AWS-IAM-IDC-UserDelegations_{timestamp}.xlsx')

with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
    # Write DataFrame to Excel
    df.to_excel(writer, sheet_name='User Assignments', index=False)
    
    # Get workbook and worksheet objects to apply formatting
    workbook = writer.book
    worksheet = writer.sheets['User Assignments']
    
    # Add some formatting
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#D3D3D3',
        'border': 1
    })
    
    # Format the header row
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(0, col_num, value, header_format)
    
    # Adjust column widths
    for idx, col in enumerate(df.columns):
        max_length = max(
            df[col].astype(str).apply(len).max(),
            len(col)
        )
        worksheet.set_column(idx, idx, max_length + 2)


print(f"Excel report has been generated: {output_file}")