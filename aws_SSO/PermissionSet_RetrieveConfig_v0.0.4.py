import boto3
import json
import os
import sys
from pprint import pprint
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas as pd
from datetime import datetime
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)
from helpers.helper import validate_sso_token, get_org_account_list

# Configure output path
OUTPUT_PATH = r"C:\Users\sgwalls\Documents\AWS_Projects\Scripts\Python\exports\PermissionSetConfigs"
datetime.datetime(2020, 3, 24, 20, 25, 35, 559000, tzinfo=tzlocal())
class PermissionSet:
    def __init__(self, Name=None, Description=None, SessionDuration=None, RelayState=None, ManagedPolicies=None, CustomerManagedPolicyReferences=None, InlinePolicy=None, PermissionsBoundary=None):
        self.Name = Name
        self.Description = Description
        self.SessionDuration = SessionDuration
        self.RelayState = RelayState
        self.ManagedPolicies = ManagedPolicies
        self.CustomerManagedPolicyReferences = CustomerManagedPolicyReferences
        self.InlinePolicy = InlinePolicy
        self.PermissionsBoundary = PermissionsBoundary

def get_permission_set_access(session, instance_arn, permission_set_arn):
    sso_admin = session.client('sso-admin') if session else boto3.client('sso-admin')
    kwargs = {}

    try:
        # Get permission set details
        permission_set = sso_admin.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )['PermissionSet']

        kwargs['Name'] = permission_set['Name']
        kwargs['Description'] = permission_set.get('Description', '')
        kwargs['SessionDuration'] = permission_set.get('SessionDuration', '')
        kwargs['RelayState'] = permission_set.get('RelayState', '')

        # Get AWS managed policies
        managed_policies = sso_admin.list_managed_policies_in_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        if managed_policies['AttachedManagedPolicies']:
            kwargs['ManagedPolicies'] = [
                policy['Arn'] for policy in managed_policies['AttachedManagedPolicies']
            ]

        # Get customer managed policies
        customer_managed_policies = sso_admin.list_customer_managed_policy_references_in_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        if customer_managed_policies['CustomerManagedPolicyReferences']:
            kwargs['CustomerManagedPolicyReferences'] = customer_managed_policies['CustomerManagedPolicyReferences']

        # Get inline policy
        inline_policy = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        if inline_policy.get('InlinePolicy'):
            kwargs['InlinePolicy'] = json.loads(inline_policy['InlinePolicy'])

        # Get permissions boundary
        try:
            permissions_boundary = sso_admin.get_permissions_boundary_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            if permissions_boundary.get('PermissionsBoundary'):
                kwargs['PermissionsBoundary'] = permissions_boundary['PermissionsBoundary']
        except sso_admin.exceptions.ResourceNotFoundException:
            # No permissions boundary set
            pass

        return kwargs

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def export_to_excel(permission_sets_data, filename=None, output_path=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"PermissionSets_Export_{timestamp}.xlsx"
    
    if output_path:
        os.makedirs(output_path, exist_ok=True)
        filename = os.path.join(output_path, filename)
    
    # Convert to DataFrame for easier Excel export
    df_data = []
    for ps in permission_sets_data:
        row = {
            'Name': ps.Name,
            'Description': ps.Description,
            'SessionDuration': ps.SessionDuration,
            'RelayState': ps.RelayState,
            'ManagedPolicies': ', '.join(ps.ManagedPolicies) if ps.ManagedPolicies else '',
            'CustomerManagedPolicies': str(ps.CustomerManagedPolicyReferences) if ps.CustomerManagedPolicyReferences else '',
            'HasInlinePolicy':  ps.InlinePolicy,
            'PermissionsBoundary': str(ps.PermissionsBoundary) if ps.PermissionsBoundary else ''
        }
        df_data.append(row)
    
    df = pd.DataFrame(df_data)
    df.to_excel(filename, index=False, sheet_name='Permission Sets')
    print(f"Permission sets exported to: {filename}")
    return filename

session = boto3.Session(profile_name='gloca_master',region_name='us-west-2')
validate_sso_token(session)
sso = session.client('sso-admin')
permission_sets = []
sso_instances = sso.list_instances()['Instances']
instance_arn = sso_instances[0]['InstanceArn']
permission_sets = []
response = sso.list_permission_sets(InstanceArn=instance_arn, MaxResults=100)
permission_sets.extend(response['PermissionSets'])
while 'NextToken' in response:
    response = sso.list_permission_sets(InstanceArn=instance_arn, MaxResults=100, NextToken=response['NextToken'])
    permission_sets.extend(response['PermissionSets'])

permission_sets_data = []
for permission_set_arn in permission_sets:
    access_kwargs = get_permission_set_access(session, instance_arn, permission_set_arn)
    
    if access_kwargs:
        permissionSet = PermissionSet(**access_kwargs)
        permission_sets_data.append(permissionSet)
        pprint(permissionSet.__dict__, width=100, sort_dicts=False)
    else:
        print("Failed to retrieve permission set access details.")

# Export to Excel
export_to_excel(permission_sets_data, output_path=OUTPUT_PATH)