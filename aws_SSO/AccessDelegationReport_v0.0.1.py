import boto3
from retriever import validate_sso_token

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


session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)
sso = session.client('sso-admin')
identity_store = session.client('identitystore')
instance_list = get_sso_instance_list()
for instance in instance_list:
    instance_details = instance

identity_store_id = instance_details['IdentityStoreId']
group_list = get_group_list(identity_store_id)
permission_set_dict = {}
for group in group_list:
    group_details = group
    group_id = group_details['GroupId']
    group_name = group_details['DisplayName']
    assignments = get_assignments_for_principal(group_id, 'GROUP', instance_details['InstanceArn'])
    for assignment in assignments:
        if not permission_set_dict.get(assignment['PermissionSetArn']):
            permission_set_dict[assignment['PermissionSetArn']] = get_permission_set_name(instance_details['InstanceArn'], assignment['PermissionSetArn'])
        print(f"Group: {group_name}, PermissionSet: {permission_set_dict[assignment['PermissionSetArn']]}, AccountId: {assignment['AccountId']}")


