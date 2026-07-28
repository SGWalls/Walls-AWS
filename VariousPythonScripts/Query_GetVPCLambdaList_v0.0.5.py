import boto3
import json
import os
import logging
import time
import pandas as pd
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from concurrent.futures import ThreadPoolExecutor, as_completed
from retriever import Account
from retriever import get_org_account_list
from retriever import validate_sso_token

userprofile = os.environ["USERPROFILE"]

def export_to_excel(data_set, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Lambdas_without_VPC{timestamp}.xlsx"
    
    # Convert to DataFrame for easier Excel export
    df_data = []
    for data_item in data_set:
        df_data.append(data_item)
    
    df = pd.DataFrame(df_data)
    df.to_excel(filename, index=False, sheet_name='LambdasWithoutVPC')
    print(f"Data exported to: {filename}")
    return filename

def get_functions(self):
    client = self.client_config('lambda')
    function_list = []
    vpc_functs = []
    paginator = client.get_paginator('list_functions')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        function_list.extend([funct['FunctionName'] for funct in 
                                page['Functions']])
        vpc_functs.extend([funct['FunctionName'] for funct in 
                            page['Functions'] if (funct.get('VpcConfig') and funct.get('VpcConfig').get('VpcId'))])
        non_vpc_functs = [funct for funct in function_list if funct not in vpc_functs]
    self.all_functions = function_list
    self.vpc_functions = vpc_functs
    self.non_vpc_functions = []

    if non_vpc_functs:
        for funct in non_vpc_functs:
            funct_dict = { 
                "AccountName": self.accountName,
                "AccountId": self.account_id,
                "FunctionName": funct
            }
            self.non_vpc_functions.append(funct_dict)


def delimiter(symbol='='):
    logger.info(symbol * 120)

def test_token(session=boto3):
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

def name_generator(preferredName,prefix=None,suffix=None):
    return (prefix if prefix else "" ) + preferredName + (suffix if suffix else "")

data_filename = (f"Lambdas_without_VPC-"
                   f"{datetime.now().strftime('%Y%m%d-%H%M')}.xlsx")
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Exports\\LambdaVPCStatus\\"
)
if not os.path.exists(export_path):
    os.makedirs(export_path)
attach_completeFilePath = os.path.join(export_path, data_filename)

logger = logging.getLogger('AWSLogging')
logger.setLevel(logging.INFO)
region = 'us-west-2'


session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)
account_list = get_org_account_list(session)
non_vpc_functs = []
# account_list = [
#     {'Id':'588755084939'},
#     {'Id':'683228415736'}
# ]

# for account in account_list:
def process_account(account, session):
    current_account = Account(account_id=account['Id'],
                        session=session,
                        sessionName='ADMSGWALLS-VPCLambdaQuery',
                        roleName='AWSControlTowerExecution',
                        region='us-west-2'
                        )
    current_account.accountName = account['Name']
    get_functions(current_account)
    
    non_vpc_functs.extend(current_account.non_vpc_functions)

max_workers = 10  # Adjust based on your needs
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_account, account, session) 
               for account in account_list]
    for future in as_completed(futures):
        try:
            future.result()
        except Exception as e:
            logger.error(f"Error processing account: {e}")

# print(non_vpc_functs)
export_to_excel(non_vpc_functs,filename=attach_completeFilePath)