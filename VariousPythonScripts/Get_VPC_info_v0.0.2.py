import boto3
import os
import time
import json
import logging
import pandas as pd
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "get_VPC-Cidr_info\\"
)
log_file_name = f"Gather-VPC-CIDR-blocks{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


def delimiter(symbol='='):
    logger.info(symbol * 120)


def handle_dry_run(error):
    logger.info(f"Operation: {error.operation_name}")
    logger.info(f"{error.response['Error']['Message']}")


def create_filter(name=None, values=None):
    if values is None:
        values = []
    return {
        "Name": name,
        # Values: [values]
        "Values": values
    }


def create_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
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


def assume_role(account_identifier, session_name, duration=900):
    credential_response = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_identifier}:role/{role_name}",
        RoleSessionName=session_name,
        DurationSeconds=duration
    )['Credentials']
    response = {
        'aws_access_key_id': credential_response['AccessKeyId'],
        'aws_secret_access_key': credential_response['SecretAccessKey'],
        'aws_session_token': credential_response['SessionToken'],
    }
    return response

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


def get_accounts(root_identifier):
    target_ou_id_list = [
        ou['Id'] for ou in org.list_organizational_units_for_parent(
            ParentId=root_identifier)['OrganizationalUnits']
    ]
    target_account_list = []
    for ou_id in target_ou_id_list:
        list_of_accounts = org.list_accounts_for_parent(
            ParentId=ou_id
        )['Accounts']
        target_account_list.extend(list_of_accounts)
    return target_account_list


region = 'us-west-2'
logger = create_logger('ad_connector_query_logger')
root_ids = ['r-mdy1', 'r-7w8p']
ec2 = {}
vpc_info = {}
for root_id in root_ids:
    if root_id == "r-mdy1":
        role_name = 'AWSControlTowerExecution'
        session = boto3.session.Session(
            profile_name='ct_master',
            region_name=region
        )
        test_token(session)
        org_label = 'ct'
        account_list = [{'Name': 'Globe Life','Id':'662627786878'}]
        # account_id_list = ['662627786878'] 
    elif root_id == "r-7w8p":
        role_name = 'OrganizationAccountAccessRole'
        session = boto3.session.Session(
            profile_name='master',
            region_name=region
        )
        org_label = 'leg'
        account_list = [{'Name': 'TorchmarkAWS','Id':'741252614647'}]
        # account_id_list = ['741252614647']
    else:
        raise ValueError(
            'Invalid Root ID. ID is either incorrect or'
            'does not belong to Globe-owned AWS Organizations'
        )
    org = session.client('organizations')
    sts = session.client('sts')
    try:
        token_test = sts.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")   
    account_list.extend(get_accounts(root_id))
    account_id_list = [identifier['Id'] for identifier in account_list]
    for account_id in account_id_list:
        if account_id not in ['662627786878', '741252614647']:
            credentials = assume_role(
                account_id,
                session_name='get_connectors'
            )
            ec2[account_id] = boto3.client('ec2',
                            **credentials,
                            region_name=region
                            )
        else:
            ec2[account_id] = session.client('ec2')
        account_name = [
        account['Name'] for account in account_list 
        if account_id in account['Id']
        ]
        vpc_info_key = f"{account_name[0]}-{account_id}"
        vpc_list = ec2[account_id].describe_vpcs(
                            Filters=[
                                create_filter('state',['available'])
                            ]
                                        )['Vpcs']
        if vpc_list:
            vpc_info[vpc_info_key] = [
                vpc['CidrBlock']
                for vpc in vpc_list
            ]    
# logger.info(vpc_info)
filename = (f"VPC_CIDR_info-{org_label}_org11082021.json")
excelfilename = ("VPC_CIDR_info_11082021.xlsx")
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "get_VPC-Cidr_info\\"
)
df_vpcinfo = pd.DataFrame.from_dict(vpc_info, orient='index')
# df_vpcinfo = (df_vpcinfo.T)
print(df_vpcinfo)
completeFilePath = os.path.join(export_path, filename)
excelfilepath = os.path.join(export_path, excelfilename)    
df_vpcinfo.to_excel(excelfilepath)
with open(completeFilePath, "w") as f:
    f.write(
        json.dumps(vpc_info, sort_keys=True, indent=4, default=str
        )
    )


