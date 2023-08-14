import boto3
import json
import os
import logging


def check_statement(statement):
    new_statement = {}
    new_statement.update(statement)    
    if 's3:PutObject' in statement['Action']:
        new_statement['Resource'] = list()
        # print(statement)
        if isinstance(statement['Resource'],list):
            for resource in statement['Resource']:
                if 'PAS-Complete' in resource:
                    print(resource.replace(resource[-14:],'*'))
                    print('PAS-Complete is present') 
                    new_statement['Resource'].append(resource.replace(resource[-14:],'*'))
                else:
                    new_statement['Resource'].append(resource)
            return new_statement
        else:
            if 'PAS-Complete' in statement['Resource']:
                print(statement['Resource'].replace(statement['Resource'][-14:],'*'))
                print('PAS-Complete is present')
                new_statement['Resource'].append(statement['Resource'].replace(statement['Resource'][-14:],'*'))
            else:
                new_statement['Resource'].append(statement['Resource'])
        return new_statement
    return new_statement

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

environment_mappings = {
    'dev': {
        'AccountId' : '896172592430',
        'UserNamePrefix': 'Informatica_DEV_',
        'ProfileName' : 'cdm_dev'
    },
    'test': {
        'AccountId' : '856695471500',
        'UserNamePrefix': 'Informatica_TST_',
        'ProfileName' : 'cdm_test'
    },
    'prod':{
        'AccountId' : '838001389413',
        'UserNamePrefix' : 'Informatica_PRD_',
        'ProfileName' : 'cdm_prod'
    }
}

endFlag = False
account_env = input(
    'Which environment is this targetting? ([D]EV [T]EST [S]TAGE [P]ROD) '
).lower()
if account_env == 'd':
    account_env = 'dev'
elif account_env == 't':
    account_env = 'test'
elif account_env == 's':
    account_env = 'stage'
elif account_env == 'p':
    account_env = 'prod'

    
session = boto3.Session(
    profile_name=environment_mappings[account_env]['ProfileName'],
    region_name='us-west-2'
)
iam = session.client('iam')
user_list = []
for user in iam.list_users()['Users']:        
    if user['UserName'].startswith(environment_mappings[account_env]['UserNamePrefix']):
            print(user['UserName'])
            user_policy = iam.get_user_policy(
                    UserName=user['UserName'],
                    PolicyName=(
                        get_policy_name(
                            iam.list_user_policies(UserName=user['UserName']
                    )['PolicyNames']))
                )
            policy_document = user_policy['PolicyDocument']
            print(policy_document)
            new_policy_document = {}
            new_policy_document['Version'] = policy_document['Version']
            new_policy_document['Statement'] = []
            for statement in policy_document['Statement']:
                new_policy_document['Statement'].append(check_statement(statement))
            print(new_policy_document)
            if policy_document != new_policy_document:
                print('!!!policy has changed!!!')
                # iam.put_user_policy(
                #     UserName = user_policy['UserName'],
                #     PolicyName = user_policy['PolicyName'],
                #     PolicyDocument = json.dumps(new_policy_document)
                # )
            end_choice = input("Would you like to continue? Y/N  ")
            if end_choice.lower() == 'y':
                continue
            else:
                break
