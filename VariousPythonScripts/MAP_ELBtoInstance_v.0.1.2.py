import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()
        self.loadBalancers = self.map_elb_to_instance()

    def get_credentials(self):
        return self.assume_role('ent_elb_query')

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )

    def get_name(self,identifier,accountId):
        tagMappings = self.client_config('resourcegroupstaggingapi').get_resources(
            ResourceARNList=[
                f'arn:aws:ec2:us-west-2:{accountId}:instance/{identifier}'
            ]
        )['ResourceTagMappingList']
        for tags in tagMappings:
            for tag in tags['Tags']:
                name=None
                if not name:
                    name = tag['Value'] if (tag['Key'] == 'Name') else None
        return name

    def map_elb_to_instance(self):
        elb = self.client_config('elbv2')
        elb_list = [lb for lb in elb.describe_load_balancers()['LoadBalancers'] if lb.get('Scheme') == 'internet-facing']
        response_list = [] 
        for loadBalancer in elb_list:
            targetGroups = elb.describe_target_groups(LoadBalancerArn=loadBalancer['LoadBalancerArn'])['TargetGroups']
            lbDetail = {
                'LoadBalancerArn': loadBalancer['LoadBalancerArn']
            }
            lbDetail['Instances'] = []
            for group in targetGroups:        
                tarHealthDescriptions = elb.describe_target_health(
                                    TargetGroupArn=group['TargetGroupArn']
                                    )['TargetHealthDescriptions']
                for target in tarHealthDescriptions:
                    lbDetail['Instances'].append({
                        'InstanceId': target['Target']['Id'],
                        'InstanceName': self.get_name(target['Target']['Id'],accountId=self.account_id)
                    })
            response_list.append(lbDetail)
        return response_list
    

def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def delimiter(symbol='='):
    logger.info(symbol * 120)


logger = logging.getLogger()
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
pub_lbs = {}

for page in iterator:
    for account in page['Accounts']:
        accounts.append(account['Id'])

for account in accounts:
    if account != "662627786878":
        accnt = Account(account,session)
        if accnt.loadBalancers:
            pub_lbs[accnt.account_id] = accnt.loadBalancers

# elb = session.client('elbv2')
# pub_lbs = {}
# accountId='166639160687'
# tagging = session.client('resourcegroupstaggingapi')

# def get_name(identifier,accountId):
#     tagMappings = tagging.get_resources(
#         ResourceARNList=[
#             f'arn:aws:ec2:us-west-2:{accountId}:instance/{identifier}'
#         ]
#     )['ResourceTagMappingList']
#     for tags in tagMappings:
#         for tag in tags['Tags']:
#             name=None
#             if not name:
#                 name = tag['Value'] if (tag['Key'] == 'Name') else None
#     return name


print(pub_lbs)