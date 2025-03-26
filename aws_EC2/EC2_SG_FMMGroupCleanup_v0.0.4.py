import boto3
import os
import datetime
import logging
from botocore.exceptions import ClientError
from typing import List
from retriever import validate_sso_token, get_org_account_list
from concurrent.futures import ThreadPoolExecutor
import threading

LOG_LEVEL = logging.INFO
userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\EC2_FMM_SecGroupCleanup\\"
    )
log_file_name = f"ec2-FMMSecGroupCleanup-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


addtl_accounts = [
    {
        'Id':'437833767532',
        'Arn':'arn:aws:organizations::741252614647:account/o-tuwjxnhqr4/741252614647',
        'Email': 'TorchmarkAWS@torchmarkcorp.com',
        'Name': 'PRD_PolySystems',
        'Status':'ACTIVE',
        'JoinedMethod': 'INVITED',
        'JoinedTimestamp': '2018-10-09T16:21:23.832000-05:00'
    }
]

def create_logger(logger_name,log_path,log_file_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.WARNING)
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

def remove_security_groups_from_nic(network_interface_info, security_group_ids: List[str], client):
    """
    Removes specified security groups from a network interface if they are attached.
    
    Args:
        network_interface_id (str): The ID of the network interface
        security_group_ids (List[str]): List of security group IDs to remove
        
    Returns:
        tuple[bool, List[str]]: 
            - Boolean indicating if any changes were made
            - List of security group IDs that were actually removed
            
    Raises:
        ClientError: If there's an AWS API error
        ValueError: If removing groups would leave interface with no security groups
    """
    try:        
        # Get current security groups attached to the network interface
        response = network_interface_info
        network_interface_id = response['NetworkInterfaceId']
            
        current_groups = response['Groups']
        current_group_ids = [group['GroupId'] for group in current_groups]
        
        # Find which of the specified groups are actually attached
        groups_to_remove = set(security_group_ids) & set(current_group_ids)
        
        # If none of the specified groups are attached, return early
        if not groups_to_remove:
            return False, []
            
        # Calculate the new group list
        new_groups = [gid for gid in current_group_ids if gid not in groups_to_remove]
        
        # Check if removing these groups would leave the interface with no security groups
        if not new_groups:
            logger.info(
                f"-={network_interface_id}=- : Cannot remove all specified security groups as it would leave the "
                "network interface with no security groups attached"
            )
            groups_to_remove = []
            
        # Update the network interface with the new security group list
        client.modify_network_interface_attribute(
            NetworkInterfaceId=network_interface_id,
            Groups=new_groups
        )
        
        return True, list(groups_to_remove)
        
    except ClientError as e:
        logger.info(f"Error removing security groups: {e}")
        raise

def get_all_security_groups(ec2):
    paginator = ec2.get_paginator('describe_security_groups')
    sg_list = []
    for page in paginator.paginate():
        sg_list.extend(page["SecurityGroups"])
    return sg_list

def get_all_network_interfaces(ec2):
    paginator = ec2.get_paginator('describe_network_interfaces')
    nic_list = []
    for page in paginator.paginate():
        nic_list.extend(page["NetworkInterfaces"])
    return nic_list

def process_account(account, session):
    try:
        sts = session.client('sts')
        assumed_role = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account['Id']}:role/AWSControlTowerExecution",
            RoleSessionName="FMMSGcleanup"
        )
        assumed_session = boto3.Session(        
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken'],
        region_name='us-west-2'
        )
        logger.info(f"AccountId: {account['Id']}, AccountName: {account['Name']}")
        ec2 = assumed_session.client('ec2')


        sg_list = get_all_security_groups(ec2)

        sg_final_list = [
            sg for sg in sg_list 
            if any(sg['GroupName'].startswith(prefix) for prefix in sg_prefix_list)
        ]
        sg_final_dict = {
            sg['GroupId']: sg['GroupName'] 
            for sg in sg_list 
            if any(sg['GroupName'].startswith(prefix) for prefix in sg_prefix_set)
        }
        if sg_final_dict:
            logger.warning(f"-={account['Id']}=- {sg_final_dict}")
        nic_list = get_all_network_interfaces(ec2)
                
        for nic in nic_list:
            if nic['InterfaceType'] == "lambda":
                logger.info(f"-={account['Id']}=- NIC ID: {nic['NetworkInterfaceId']} is a Lambda Function")
                continue
            nic_id = nic["NetworkInterfaceId"]
            nic_sg_list = [sg["GroupId"] for sg in nic["Groups"]]
            logger.info(f"-={account['Id']}=- NIC ID: {nic_id}")
            # logger.info(f"NIC SGs: {nic_sg_list}")
            status,removed_sg = remove_security_groups_from_nic(nic,sg_final_dict.keys(),ec2)
            if status:
                logger.info(f"-={account['Id']}=- Removed SGs: {removed_sg} from NIC with ID: {nic_id}")
        for sg_id in sg_final_dict.keys():
            try:
                ec2.delete_security_group(
                    GroupId=sg_id
                )
                logger.info(f"-={account['Id']}=- Deleted Security Group: {sg_id}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'DependencyViolation':
                    logger.warning(f"-={account['Id']}=- Security Group {sg_id} has dependencies and cannot be deleted.")
                else:
                    logger.info(f"-={account['Id']}=- Error deleting security group {sg_id}: {e}")
        #     choice = input(f"Continue with deleting security Group with id {sg_id} and name {sg_final_dict[sg_id]}: ").lower()
        #     if choice in ["","y"]:
        #         ec2.delete_security_group(
        #             GroupId=sg_id
        #         )
        #     elif choice == "n":
        #         continue
        #     else:
        #         logger.info("Invalid input")
    except Exception as e:
        logger.info(f"Error processing account {account['Id']}: {e}")

def process_all_accounts(account_list, session):
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(lambda acc: process_account(acc, session), account_list)


logger = create_logger('Logging',log_path,log_file_name)
sg_prefix_list = [
    "FMManagedSecurityGroup17859c5e-6e22-4f48-9f36-c5d1104e2446-sg-03f983933483da9ca",
    "FMManagedSecurityGroup44667565-8b31-4310-adbc-0235a288cacc-sg-07240bb9c495f4821",
    "FMManagedSecurityGroupc3fbdb88-1d07-44f7-a165-d34215cd3091-sg-074615d0a09de8723",
    "FMManagedSecurityGroup15412b96-8036-4027-9306-c9b9e5b7bd77-sg-0da01e18e277c29f7"
]
sg_prefix_set = set(sg_prefix_list)

session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
validate_sso_token(session)
account_list = get_org_account_list(session)
# account_list = addtl_accounts
sts = session.client('sts')

process_all_accounts(account_list, session)

# for account in account_list:
#     assumed_role = sts.assume_role(
#         RoleArn=f"arn:aws:iam::{account['Id']}:role/AWSControlTowerExecution",
#         RoleSessionName="FMMSGcleanup"
#     )
#     assumed_session = boto3.Session(        
#         aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
#         aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
#         aws_session_token=assumed_role['Credentials']['SessionToken'],
#         region_name='us-west-2'
#     )
#     logger.info(f"AccountId: {account['Id']}, AccountName: {account['Name']}")
#     ec2 = assumed_session.client('ec2')

#     response = ec2.describe_security_groups()
#     sg_list = response["SecurityGroups"]
#     while "NextToken" in response:
#             response = ec2.describe_security_groups(NextToken=response['NextToken'])
#             sg_list.extend(response["SecurityGroups"])

#     sg_final_list = [
#         sg for sg in sg_list 
#         if any(sg['GroupName'].startswith(prefix) for prefix in sg_prefix_list)
#     ]
#     sg_final_dict = {sg['GroupId']:sg['GroupName'] for sg in sg_list if sg['GroupName'][:79] in sg_prefix_list}
#     logger.info(sg_final_dict)
#     network_attachments = ec2.describe_network_interfaces()
#     nic_list = network_attachments["NetworkInterfaces"]
#     while "NextToken" in network_attachments:
#             network_attachments = ec2.describe_network_interfaces(NextToken=network_attachments['NextToken'])
#             nic_list.extend(network_attachments["NetworkInterfaces"])
            
#     for nic in nic_list:
#         nic_id = nic["NetworkInterfaceId"]
#         nic_sg_list = [sg["GroupId"] for sg in nic["Groups"]]
#         logger.info(f"NIC ID: {nic_id}")
#         # logger.info(f"NIC SGs: {nic_sg_list}")
#         status,removed_sg = remove_security_groups_from_nic(nic,sg_final_dict.keys(),ec2)
#         if status:
#             logger.info(f"Removed SGs: {removed_sg}")
    # for sg_id in sg_final_dict.keys():
    #     choice = input(f"Continue with deleting security Group with id {sg_id} and name {sg_final_dict[sg_id]}: ").lower()
    #     if choice in ["","y"]:
    #         ec2.delete_security_group(
    #             GroupId=sg_id
    #         )
    #     elif choice == "n":
    #         continue
    #     else:
    #         logger.info("Invalid input")