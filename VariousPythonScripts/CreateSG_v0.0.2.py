import boto3
import os
import logging
from configparser import ConfigParser
from PyInquirer import prompt
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


logger = logging.getLogger()


def delimiter(symbol='='):
    logger.info(symbol * 120)

userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"

def awscliv2_exists():
    # Return True if AWSCLIv2 is installed
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )

def check_input(inpt: str):
    if inpt:
        return True
    else:
        print("Input is empty!")
        return False


def check_format(accountId):
    if (len(accountId) == 12 and accountId.isdigit()):
        return True
    else:
        print("Account ID is INVALID!")
        return False


def append_profiles(filepath, account_id, account_name, role_name, filetype="config"):
    delimiter()
    print("Adding profile to your aws config file")
    config = ConfigParser()
    config.read(filepath)
    if filetype.lower() == "config":
        profile = "profile "
    if filetype.lower() == "credentials":
        profile = ""
    config[f"{profile}{account_name}"] = dict(
        sso_session = 'glb_session',
        sso_start_url = "https://globeaws.awsapps.com/start",
        sso_region = region,
        sso_account_id = account_id,
        sso_role_name = role_name,
        region = region,
        ca_bundle = "C:\\Program Files\\Amazon\\AWSCLIV2\\nskp_config\\netskope-cert-bundle.pem",
        output = "json",
    )
    
    with open(filepath, "w") as configfile:
        config.write(configfile)
    
    delimiter()
    print(f"Added profile {profile}{account_name} to your aws config file")


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


def get_ipranges(ipblocks):
    ipranges=[]
    for ipblock in ipblocks:
        iprange = {
            'CidrIp': ipblock,
            'Description': f'Allows access from {ipblock}'
        }
        ipranges.append(iprange)
    return ipranges

def get_vpc_list(session):
    """Get list of VPCs in the account"""
    ec2 = session.client('ec2')
    response = ec2.describe_vpcs()
    
    vpc_list = []
    for vpc in response['Vpcs']:
        vpc_name = 'Unnamed VPC'
        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break
        vpc_list.append({
            'id': vpc['VpcId'],
            'name': vpc_name,
            'cidr': vpc.get('CidrBlock', 'No CIDR')
        })
    return vpc_list

def select_vpc(session):
    """Display VPCs and let user select one using PyInquirer"""
    vpcs = get_vpc_list(session)
    
    # Create choices list with formatted VPC information
    choices = [
        {
            'name': f"{vpc['id']} - {vpc['name']} ({vpc['cidr']})",
            'value': vpc['id']
        }
        for vpc in vpcs
    ]
    
    questions = [
        {
            'type': 'list',
            'name': 'vpc_id',
            'message': 'Select a VPC:',
            'choices': choices,
            'pageSize': 10  # Number of items visible at once
        }
    ]
    
    answers = prompt(questions)
    return answers['vpc_id']

while True: 
    account_id = input("Enter the AWS Account ID of the Account where the error occurred: ")
    if not check_input(account_id):
        continue
    elif not check_format(account_id):
        continue
    else:
        break
target_account_name = input("Enter the of the Target Account: ")
target_account_name = target_account_name.replace(" ","_").lower()
role_name = input(
    "Name of the role you use for accessing the account (Case Sensitive):  "
)
if awscliv2_exists:
    append_profiles(aws_config_file,account_id,target_account_name,role_name)
    
session = boto3.session.Session(profile_name=target_account_name,region_name="us-west-2")
test_token(session)
ec2 = session.client('ec2')
vpc_id = select_vpc(session)
group_name = input('Enter a Name for the Security Group: ')
ipRange_list = input('Enter a list of IP Ranges to be allowed: ').split(',')
description = input("Description for Group: ")
ingress_permission = [
    {
        'FromPort': 443,
        'IpProtocol':'tcp',
        'IpRanges': get_ipranges(ipRange_list),
        'ToPort': 443        
    }
]

new_group = ec2.create_security_group(
        Description=description,
        GroupName=group_name,
        VpcId=vpc_id
    )

ec2.authorize_security_group_ingress(
    GroupId=new_group['GroupId'],
    IpPermissions=ingress_permission
)