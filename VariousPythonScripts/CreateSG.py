import boto3
import os
import logging
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


logger = logging.getLogger()


def delimiter(symbol='='):
    logger.info(symbol * 120)


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


profileName = input("Use which profile: ")
session = boto3.session.Session(profile_name=profileName,region_name="us-west-2")
test_token(session)
ec2 = session.client('ec2')
vpc_id = input('Enter VPC ID: ')
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