import boto3
import json
import os
import logging


def check_statement(statement):
    if isinstance(statement['Resource'],list):
        for resource in statement['Resource']:
            if 'PAS-Complete' in resource:
                print(resource.replace(resource[-14:],'*'))
                print('PAS-Complete is present') 
                resource.replace(resource[-14:],'*')
                return statement
    else:
        if 'PAS-Complete' in statement['Resource']:
            print(statement['Resource'].replace(statement['Resource'][-14:],'*'))
            print('PAS-Complete is present')
            statement['Resource'].replace(statement['Resource'][-14:],'*')
            return statement

def get_policy_name(PolicyList):
    print(PolicyList)
    if isinstance(PolicyList,list):
        for policy in PolicyList:
            if policy != 'Informatica_CmnUtilKey_Access':
                return policy
            else:
                continue
    else:
        return PolicyList


session = boto3.Session(profile_name='cdm_test',region_name='us-west-2')
iam = session.client('iam')
user_list = []
for user in iam.list_users()['Users']:
    if user['UserName'].startswith('Informatica_TST_lnl'):
        print(user['UserName'])
        user_list.append(user)
        policy_document = iam.get_user_policy(
                UserName=user['UserName'],
                PolicyName=(
                    get_policy_name(
                        iam.list_user_policies(UserName=user['UserName']
                )['PolicyNames']))
            )['PolicyDocument']
        print(policy_document)
        for statement in policy_document['Statement']:
            statement = check_statement(statement)
        print(policy_document)
        input('press ENTER to continue...')