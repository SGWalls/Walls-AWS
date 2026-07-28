import boto3
from retriever import Account

account_list = ['836635038545','662627786878']
session = boto3.Session(profile_name='ct_master', region_name='us-west-2')
for account in account_list:
    accnt = Account(account, session,'acl_discover')
    iam = accnt.client_config('iam')
    result = iam.list_roles()
    print(accnt.client_config('sts').get_caller_identity().get('Arn'))
    print(result['Roles'][0])
    