import boto3
import os
import logging
import datetime
import pandas as pd
from botocore.exceptions import TokenRetrievalError, SSOTokenLoadError, UnauthorizedSSOTokenError


def delimiter(symbol='='):
    logger.info(symbol * 120)


def create_logger(logger_name, log_path, log_file_name):
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


def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError, TokenRetrievalError) as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")


def get_all_fleets(appstream_client):
    fleets = []
    paginator = appstream_client.get_paginator('describe_fleets')
    for page in paginator.paginate():
        fleets.extend(page['Fleets'])
    logger.info(f"Found {len(fleets)} fleet(s)")
    return fleets


def get_fleet_enis(ec2_client, fleet_name):
    enis = []
    paginator = ec2_client.get_paginator('describe_network_interfaces')
    for page in paginator.paginate(
        Filters=[{'Name': 'description', 'Values': [f'AppStream 2.0 - fleet: {fleet_name} -*']}]
    ):
        enis.extend(page['NetworkInterfaces'])
    return enis


# --- Setup ---
userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
    "logging\\AppStream_FleetInstanceDetails\\"
)
if not os.path.exists(log_path):
    os.makedirs(log_path)

timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
log_file_name = f"AppStream_FleetInstanceDetails_{timestamp}.log"
logger = create_logger('AppStreamFleetDetails', log_path, log_file_name)

session = boto3.Session(profile_name='prd_cas', region_name='us-west-2')
test_token(session)

retry_config = boto3.session.Config(retries={'max_attempts': 10, 'mode': 'adaptive'})
appstream = session.client('appstream', config=retry_config)
ec2 = session.client('ec2', config=retry_config)

# --- Main ---
results = []
fleets = get_all_fleets(appstream)


for fleet in fleets:
    fleet_name = fleet['Name']
    fleet_state = fleet['State']
    logger.info(f"Processing fleet: {fleet_name} | State: {fleet_state}")

    enis = get_fleet_enis(ec2, fleet_name)
    logger.info(f"  Found {len(enis)} ENI(s) in fleet {fleet_name}")

    for eni in enis:
        attachment = eni.get('Attachment', {})
        results.append({
            'FleetName': fleet_name,
            'FleetState': fleet_state,
            'ENI_Id': eni.get('NetworkInterfaceId', ''),
            'Description': eni.get('Description', ''),
            'PrivateIpAddress': eni.get('PrivateIpAddress', ''),
            'PrivateDnsName': eni.get('PrivateDnsName', ''),
            'MacAddress': eni.get('MacAddress', ''),
            'Status': eni.get('Status', ''),
            'SubnetId': eni.get('SubnetId', ''),
            'VpcId': eni.get('VpcId', ''),
            'AvailabilityZone': eni.get('AvailabilityZone', ''),
            'AttachmentId': attachment.get('AttachmentId', ''),
            'AttachTime': str(attachment.get('AttachTime', '')),
            'RequesterId': eni.get('RequesterId', '')
        })

# --- Export ---
output_path = f"{userprofile}\\Documents\\AppStream_FleetInstanceDetails_{timestamp}.xlsx"
df = pd.DataFrame(results)
df.to_excel(output_path, index=False)
logger.info(f"Export complete: {output_path}")
logger.info(f"Total instances captured: {len(results)}")
