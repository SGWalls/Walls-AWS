import boto3
import os
import subprocess, shlex
import logging
import pandas as pd
from datetime import datetime

"""
Represents an AWS account and provides methods for assuming roles
and creating service clients with the appropriate credentials.
"""
class Account():
    def __init__(self, account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2"):
        self.region = region
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
        self.credentials = self.get_credentials() if account_id != '741252614647' else {
            'AccessKeyId':None,
            'SecretAccessKey':None,
            'SessionToken':None
        }
 
    def get_caller_account(self):
            try:
                return self.session.client('sts').get_caller_identity().get('Account')
            except Exception as e:
                if "expired" in str(e):
                    delimiter()
                    logger.info(e)
                    logger.info("Reinitiating SSO Login...")
                    subprocess.run(shlex.split(
                        f"aws sso login --profile {self.session.profile_name}"
                    ))
                    return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role(self.sessionName) if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

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


class HostedZones():
    def __init__(self, account):
        self.account = account
        self.client = (account.client_config('route53') if 
                       account.account_id != '741252614647' else 
                       boto3.Session(profile_name='master',
                                    region_name='us-west-2').client('route53'))

    def get_hosted_zones(self):
        paginator = self.client.get_paginator('list_hosted_zones')
        all_hosted_zones = []

        for page in paginator.paginate():
            all_hosted_zones.extend(page['HostedZones'])

        return all_hosted_zones

    # function to retrieve resource records from hosted zone
    def get_resource_records(self, zone_id):
        paginator = self.client.get_paginator('list_resource_record_sets')
        all_records = []

        for page in paginator.paginate(HostedZoneId=zone_id):
            all_records.extend(page['ResourceRecordSets'])

        return all_records

    def get_zone_id(self, zone_name):
        for zone in self.get_hosted_zones():
            if zone['Name'] == zone_name:
                return zone['Id']
        return None
    
    # function to check if resource record is an alias or not and extract it's value
    def get_resource_value(self, record):
        if record.get('AliasTarget'):
            return record['AliasTarget']['DNSName']
        elif record.get('ResourceRecords'):
            return record['ResourceRecords']

    # function to format resource records for pandas dataframe
    def format_resource_records(self, records, zone_name):
        data = []
        for record in records:
            record_value = self.get_resource_value(record)
            # Check if record_value is a list
            if isinstance(record_value, list):
                for value in record_value:
                    data.append({
                        'AccountId' : self.account.account_id,
                        'ZoneName': zone_name,
                        'Name': record['Name'],
                        'Type': record['Type'],
                        'TTL': record['TTL'] if record.get('TTL') else 'N/A',
                        'Value': value['Value']
                    })      
            # If record_value is not a list, it's a string
            else:
                data.append({
                    'AccountId' : self.account.account_id,
                    'ZoneName': zone_name,
                    'Name': record['Name'],
                    'Type': record['Type'],
                    'TTL': record['TTL'] if record.get('TTL') else 'N/A',
                    'Value': record_value
                })
        return pd.DataFrame(data)


def delimiter(symbol='='):
    logger.info(symbol * 120)

# function to generate a list of accounts in the organization
def get_accounts(session):
    client = session.client('organizations')
    accounts = []
    response = client.list_accounts()
    accounts.extend(response['Accounts'])
    while 'NextToken' in response:
        response = client.list_accounts(NextToken=response['NextToken'])
        accounts.extend(response['Accounts'])
    return accounts

logger = logging.getLogger('Logging')
session = boto3.Session(profile_name='ct_master')
# set file location for df.to_csv location
file_location = 'C:\\Users\\sgwalls\\Documents\\AWS_Projects\\exports\\R53_Data'
# check path and create if not exists
if not os.path.exists(file_location):
    os.makedirs(file_location)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = os.path.join(file_location, f'all_hosted_zones_{timestamp}.csv')
all_dfs = []


# generate account list, iterate through accounts to retrieve hosted zones and resource records
account_list = get_accounts(session)
account_list.append({'Id': '741252614647', 'Email': 'torchmarkaws_aws@torchmarkcorp.com', 'Name': 'Torchmark AWS', 'Status': 'ACTIVE'})
for account in account_list:
    account = Account(account_id=account['Id'], session=session)
    hosted_zones = HostedZones(account)
    for zone in hosted_zones.get_hosted_zones():
        zone_id = hosted_zones.get_zone_id(zone['Name'])
        if zone_id:
            records = hosted_zones.get_resource_records(zone_id)
            if records:
                df = hosted_zones.format_resource_records(records,zone['Name'])
                print(df)
                all_dfs.append(df)



combined_df = pd.concat(all_dfs, ignore_index=True)
combined_df.to_csv(output_file, index=False)
              