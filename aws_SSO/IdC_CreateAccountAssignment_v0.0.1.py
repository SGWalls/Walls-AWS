import boto3
import time
from retriever import validate_sso_token

class Assign():
    def __init__(self, session):
        self.session = session
        self.perm_set_list = self.get_permission_set_list()
        self.group_list = self.get_group_list(self.get_directory_details()['DirectoryId'])
    
    def client_config(self,service,creds=None,region='us-west-2'):
        if creds:
            response = boto3.session.Session().client(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region,
                service_name=service
            )
        else:
            response = self.session.client(
                region_name=region,
                service_name=service
            ) if self.session else boto3.session.Session().client(
                region_name=region,
                service_name=service
            )
        return response

    def get_directory_details(self):
        ds = self.client_config('ds')
        ds_response = ds.describe_directories()['DirectoryDescriptions'][0]
        return ds_response

    def get_group_details(self, group_list, group_name):
        if len(group_name) <= 9:
            print('Group name must be at least 10 characters long')
            return
        for group in group_list:
            if group['DisplayName'].lower().startswith(group_name.lower()):
                print(group['DisplayName'])
                grp_response = group
        if len(grp_response) == 0:
            print(f'Group {group_name} not found')
        else:
            return grp_response    

    def get_group_list(self, id_store_id):
        idstore = self.client_config('identitystore')
        paginator = idstore.get_paginator('list_groups')
        group_list = []
        for page in paginator.paginate(IdentityStoreId=id_store_id):
            group_list.extend(page['Groups'])
        return group_list
        
    def get_permission_set_list(self):
        sso_admin = self.client_config('sso-admin')
        instance_arn = sso_admin.list_instances(MaxResults=1)['Instances'][0]['InstanceArn']
        paginator = sso_admin.get_paginator('list_permission_sets')
        permission_set_list = []
        permission_set_final = []
        for page in paginator.paginate(InstanceArn=instance_arn):
            permission_set_list.extend(page['PermissionSets'])
        for permission in permission_set_list:
            permission_set_final.append(sso_admin.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission)['PermissionSet'])
        return permission_set_final

    def get_permission_set_detail(permission_set_list,permission_set_name):
        for pset in permission_set_list:
            if pset['Name'] == permission_set_name:
                return pset    

    def get_all_accounts(self):
        """Retrieve all accounts from AWS Organizations"""
        org_client = self.client_config('organizations')
        accounts = []
        # Handle pagination
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        return accounts


if __name__ == "__main__":
    while True:
        group_name = input('Enter group name: ')
        if len(group_name) >= 10:
            break
        else:
            print('Group name must be at least 10 characters long')
    
    while True:
        permission_set_name = input('Enter permission set name: ')
        if len(permission_set_name) >= 10:
            break
        else:
            print('Permission set name must be at least 10 characters long')

    session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
    validate_sso_token(session) 
    permission_action = Assign(session)
    sso_admin = session.client('sso-admin')
    dir_detail = permission_action.get_directory_details(session)
    instance_arn = sso_admin.list_instances(MaxResults=1)['Instances'][0]['InstanceArn']
    grp_detail = permission_action.get_group_details(session, permission_action.group_list, group_name)
    if not grp_detail:
        raise Exception('Group not found')
    permission_set_detail = permission_action.get_permission_set_detail(permission_action.permission_set_list, permission_set_name)
    print(grp_detail)
    print(permission_set_detail)
    for account in account_list:
        print(f'Assigning {grp_detail["DisplayName"]} to {account}')
        response = session.client('sso-admin').create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_detail['PermissionSetArn'],
            PrincipalType='GROUP',
            PrincipalId=grp_detail['GroupId']
        )
        time.sleep(1)
        print(response)