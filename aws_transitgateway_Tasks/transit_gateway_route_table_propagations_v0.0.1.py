import boto3
import os
import time
import json
import logging
import ipaddress
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


DRY_RUN = True

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "transit_gateway_route_table_propagations\\"
)
log_file_name = f"tgwrt-propagation-update-{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


def delimiter(symbol='='):
    logger.info(symbol * 120)


def get_current_time():
    return time.strftime('%I:%M:%S %p', time.localtime()) 


def handle_dry_run(error):
    logger.info(f"Operation: {error.operation_name}")
    logger.info(f"{error.response['Error']['Message']}")


def create_filter(name=None, values=None):
    if values is None:
        values = []
    return {
        "Name": name,
        "Values": values
    }


def create_tag(key, value):
    return {
        'Key': key,
        'Value': value
    }


def create_logger(logger_name):
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



logger = create_logger('tgwrt_propagation_update')
region = 'us-west-2'
session = boto3.session.Session(
        profile_name='ct_master',
        region_name=region
    )
org = session.client('organizations')
sts_client = session.client('sts')
net_session = boto3.session.Session(profile_name='net_svc', region_name=region)
net_ec2 = net_session.client('ec2')
net_sts_client = net_session.client('sts')
try:
    token_test = net_sts_client.get_caller_identity()
except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
    if "expired or is otherwise invalid" in str(e):
        delimiter()
        logger.info(e)
        logger.info("Reinitiating SSO Login...")
        os.system(f"aws sso login --profile {net_session.profile_name}")

attachment_list = net_ec2.get_transit_gateway_route_table_propagations(
    TransitGatewayRouteTableId='tgw-rtb-07c7a524c697e84c9'
)['TransitGatewayRouteTablePropagations']

for attachment in attachment_list:
    net_ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayRouteTableId='tgw-rtb-0ea17c0722ca0aae3',
        TransitGatewayAttachmentId=attachment['TransitGatewayAttachmentId']
    )