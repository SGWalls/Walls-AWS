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

    def get_credentials(self):
        return self.assume_role('ent_r53_queryResolverRule')

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
    
    def check_resolver_rule_association(self,ResolverRuleId):
        resolver = self.client_config('route53resolver')
        rule_associations = resolver.list_resolver_rule_associations(        
                            )['ResolverRuleAssociations']       
        if rule_associations and any(d['ResolverRuleId'] == ResolverRuleId 
                                     for d in rule_associations):
            return [rrassociation for rrassociation in rule_associations if
                    rrassociation['ResolverRuleId'] == ResolverRuleId]
        elif not rule_associations:
            return "No VPC"
        else:
            return None


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

resolverRule = 'rslvr-rr-b333b2fa07e04cddb'
logger = logging.getLogger()
session = boto3.session.Session(profile_name="ct_master",region_name="us-west-2")
org = session.client('organizations')
sso = session.client('sso-admin')
test_token(session)
paginator = org.get_paginator('list_accounts')
iterator = paginator.paginate()
accounts = []
updated_accounts ={'Accounts': []}
for page in iterator:
    for account in page['Accounts']:
        accounts.append(account['Id'])

for account in accounts:
    accnt = Account(account,session)
    resolver_rule_detail = accnt.check_resolver_rule_association(resolverRule)
    if resolver_rule_detail == "No VPC":
        print(f'{account} has NO VPC Configured')
    elif resolver_rule_detail:
        print(f'{account} has VPCs with the resolver rule associated.')
    else:
        print(f'{account} does not have associations for resolver rule with id {resolverRule}')