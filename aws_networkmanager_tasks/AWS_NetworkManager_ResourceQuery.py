from urllib import response
import boto3
import json
import os
import logging
import inspect
import time
import pandas as pd
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


ASSUMED_ROLE = "OrganizationAccountAccessRole" 
ROOT_ID = "r-7w8p"


class Account():
    def __init__(
            self, account_id, logger, master_obj=None, org_root=ROOT_ID, role_name=ASSUMED_ROLE,
            region="us-west-2"):
        self.logger = logger
        self.accountid = account_id        
        if master_obj:
            self.master = master_obj
        self.root_id = org_root
        self.rolename = role_name
        self.credentials = (self.assume_role(self.accountid,
                                "AccountQueryTasks") if 
                                self.accountid != self.master.accountId 
                                else None
                            )
        self.session = boto3.session.Session(
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name=region
        ) if self.accountid != self.master.accountId else self.master.session
        self.ec2 = self.session.client('ec2')

    def assume_role(self,account_id,session_name,duration=900):
        response = self.master.session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.rolename}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']
    
    def client_config(self,creds,service,region="us-west-2"):
        response = boto3.session.Session().client(
            aws_access_key_id = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token = creds['SessionToken'],
            region_name = region,
            service_name = service
        )
        return response

    def get_vpc_detail(self,vpcId):
        client = self.ec2
        try:
            response = client.describe_vpcs(
                VpcIds =[
                    vpcId,
                ],
            )['Vpcs']
        except Exception as e:
            return {'CidrBlock':'None'}
        return response[0]

class Master():
    def __init__(self, accountId, logger):
        self.logger = logger
        self.accountId = accountId         
        if accountId == "741252614647":
            self.session = boto3.session.Session(
                                profile_name="master",
                                region_name="us-west-2"
                            )
            self.rootId = "r-7w8p"
            self.executionRole = "OrganizationAccountAccessRole"
            self.org = self.session.client("organizations")
            self.sts = self.session.client("sts")
            self.account_list = {self.accountId:'TorchmarkAWS'}
        elif accountId == "662627786878":
            self.session = boto3.session.Session(
                                profile_name="ct_master",
                                region_name="us-west-2"
                            )
            self.get_caller_account()
            self.rootId = "r-mdy1"
            self.executionRole = "AWSControlTowerExecution"
            self.org = self.session.client("organizations")
            self.sts = self.session.client("sts")
            self.account_list = {self.accountId:'Globe Life'}
            
        else:
            print("Account ID is not a valid Master Account")
        self.get_caller_account()
        self.account_list.update(self.get_accounts())

    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
            if "expired or is otherwise invalid" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                os.system(f"aws sso login --profile {self.session.profile_name}")
                return self.session.client('sts').get_caller_identity().get('Account')

    def get_accounts(self):
        paginator = self.org.get_paginator('list_accounts')
        page_iterator = paginator.paginate()
        account_list = {}
        for page in page_iterator:
            for account in page['Accounts']:
                account_list[account['Id']] = account['Name']
        return account_list

def create_logger(logger_name,log_path,log_file_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s ::%(levelname)s:: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler = logging.FileHandler(os.path.join(log_path, log_file_name))
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def delimiter(symbol='='):
    logger.info(symbol * 120)


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
        "logging\\Get_Account_VPC_info\\"
)
log_file_name = f"Get_Account_VPC_info-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

logger = create_logger("Account_VPC_Info",log_path,log_file_name)

legacy_master = Master('741252614647', logger)
new_master = Master('662627786878', logger)

session = boto3.session.Session(profile_name='net_svc')
networkmanager = session.client('networkmanager')

paginator = networkmanager.get_paginator('get_network_resources')
page_iterator = paginator.paginate(GlobalNetworkId='global-network-0693963c4f4c0a1dc',ResourceType='transit-gateway-attachment')
resources_list = []

for page in page_iterator:
    for resource in page['NetworkResources']:
        # print(resource)
        master_acct = (legacy_master if resource['AccountId'] in 
            legacy_master.account_list else (new_master if 
            resource['AccountId'] in new_master.account_list 
            else None))
        # if any(resource['AccountId'] in keys for keys in legacy_master.account_list):
        #     master_acct = legacy_master 
        # elif any(resource['AccountId'] in keys for keys in new_master.account_list):
        #     master_acct = new_master
        # else:
        #     print(f"{resource['AccountId']} is not a member of the Globe LIfe Org")
        #     master_acct = None
        resource_detail = json.loads(resource['Definition'])
        if not master_acct:
            details ={
                'AccountId':resource_detail['resourceOwnerId'],
                'AccountName':'Account Not in Globe Life Org',
                'VPC-Id':resource_detail['resourceId'],
                'CIDR-Block':'NULL'
            }
        else:
            vpc_detail = Account(
                account_id=resource_detail['resourceOwnerId'],
                logger=logger,
                master_obj=master_acct,
                role_name=(ASSUMED_ROLE if master_acct == legacy_master 
                    else "AWSControlTowerExecution")
                )
            vpc_detail.vpc_info = vpc_detail.get_vpc_detail(resource_detail['resourceId'])
            details = {
                'AccountId':vpc_detail.accountid,
                'AccountName':master_acct.account_list[vpc_detail.accountid],
                'VPC-Id':resource_detail['resourceId'],
                'CIDR-Block':vpc_detail.vpc_info['CidrBlock']
                }            
        resources_list.append(details)
print(resources_list)
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "get_VPC-Cidr_info\\"
)
excelfilename = (f"VPC_CIDR_info_{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.xlsx")
excelfilepath = os.path.join(export_path, excelfilename)    
df_vpcinfo = pd.DataFrame(resources_list)
df_vpcinfo.to_excel(excelfilepath)

# print(len(resources_list))