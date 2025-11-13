import boto3
import logging
import os
from datetime import datetime
from retriever import Account,get_org_account_list,create_logger


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\ssm_EnablePublicAccessBlock\\"
    )
log_file_name = f"ssm-EnablePublicAccessBlock-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
logger = create_logger('ssmLogger',log_path,log_file_name)

region_list = ['us-west-2','us-west-1','us-east-1','us-east-2']
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')

# account_list = get_org_account_list(session)
account_list = [{'Id':'172065884183'}]
for account in account_list:
    accnt = Account(account['Id'],session=session,roleName='AWSControlTowerExecution')
    for region_itr in region_list:
        ssm = accnt.client_config('ssm',region=region_itr)
        try:
            logger.info(f'Enabling public access block for SSM documents in account {accnt.account_id} for region {region_itr}')
            response = ssm.update_service_setting(
                SettingId='/ssm/documents/console/public-sharing-permission',
                SettingValue='Disable'
            )
            logger.info(response)
            logger.info(f'-=[ {region_itr} ]=---=Public Block Enabled=--')
        except Exception as e: 
            logger.info(e)
