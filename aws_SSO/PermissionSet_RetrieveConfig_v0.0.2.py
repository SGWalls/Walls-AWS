import boto3
import json
from pprint import pprint


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

def get_permission_set_access(instance_arn, permission_set_arn):
    sso_admin = boto3.client('sso-admin')
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

session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
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


permission_set_arn = permission_sets[0]

access_kwargs = get_permission_set_access(instance_arn, permission_set_arn)

if access_kwargs:
    print("Permission set access details:")
    # for key, value in access_kwargs.items():
    #     print(f"{key}: {value}")
    permissionSet = PermissionSet(**access_kwargs)
    pprint(permissionSet.__dict__, width=100, sort_dicts=False)
    # pprint(access_kwargs, width=100, sort_dicts=False)

    # You can now use access_kwargs to create a new permission set
    # new_permission_set = sso_admin.create_permission_set(
    #     InstanceArn=instance_arn,
    #     **access_kwargs
    # )
else:
    print("Failed to retrieve permission set access details.")