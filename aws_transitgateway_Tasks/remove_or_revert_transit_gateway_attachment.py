import boto3
import os
import time
import json
import logging
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from py import process

DRY_RUN = False


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "transit_gateway_attachment_deploy\\remove_tgw_attachment_logs\\"
)
log_file_name = f"remove_tgw-attachment{datetime.now().strftime('%Y%m%d')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)


def delimiter(symbol='='):
    logger.info(symbol * 120)


def handle_dry_run(error):
    # delimiter()
    logger.info(f"Operation: {error.operation_name}")
    logger.info(f"{error.response['Error']['Message']}")
    # delimiter()


def create_filter(name=None, values=None):
    if values is None:
        values = []
    return {
        "Name": name,
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
    except Exception as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def delete_attachment(old_attachment_id):
    delimiter()
    logger.info(
        f"START -- DELETING attachment with id {old_attachment_id}"
    )
    try:
        if ec2.delete_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId=old_attachment_id,
            DryRun=DRY_RUN
        ):
            logger.info("END -- DELETED")
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            handle_dry_run(e)


def revert_tgw_route(cidrBlock,routeTableId):
    try:
        response = net_ec2.delete_transit_gateway_route(
            TransitGatewayRouteTableId=routeTableId,
            DestinationCidrBlock=cidrBlock,
            DryRun=DRY_RUN
        )['Route']
        logger.info(f"Successfully removed Route {cidrBlock} in Transit "
                    f"Gateway Route Table {routeTableId}.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            handle_dry_run(e)
        elif e.response['Error']['Code'] == 'InvalidRoute.NotFound':
            logger.error(f"{e.response['Error']['Message']}")    
    return


def revert_attachment(sourceDetails, targetDetails):
    vpc_identifier = targetDetails[0]['VpcId']
    new_target = targetDetails[0]['TransitGatewayId']
    old_target = sourceDetails[0]['TransitGatewayId']
    route_table_list = [
        rt for rt in ec2.describe_route_tables(Filters=[
            create_filter('route.transit-gateway-id', [old_target]),
            create_filter('vpc-id', [vpc_identifier])
        ])['RouteTables']
    ]
    for table in route_table_list:
        for route in table['Routes']:
            if 'TransitGatewayId' in route.keys():
                target_route = ec2_resource.Route(
                    table['RouteTableId'],
                    route['DestinationCidrBlock']
                )
                try:
                    logger.info(f"Replacing the target for the route which "
                                    f"has the following destination CIDR: "
                                    f" {route['DestinationCidrBlock']} from "
                                     "the table with ID: "
                                    f"{table['RouteTableId']}")
                    target_route.replace(
                        TransitGatewayId=new_target,
                        DryRun=DRY_RUN
                    )
                except ClientError as e:
                    if e.response['Error']['Code'] == 'DryRunOperation':
                        handle_dry_run(e)
                    else:
                        raise
    try:
        net_ec2.enable_transit_gateway_route_table_propagation(
            TransitGatewayRouteTableId='tgw-rtb-07c7a524c697e84c9',
            TransitGatewayAttachmentId=targetDetails[0]['TransitGatewayAttachmentId'],
            DryRun=DRY_RUN
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            handle_dry_run(e)
        else:
            raise
    return 


logger = create_logger('removeTGWa')
region = 'us-west-2'
root_id = input("Please input the Root ID: ")
process_choice = input("Do you want to Delete or Revert?: ")
if root_id == "r-mdy1":
    role_name = 'AWSControlTowerExecution'
    session = boto3.session.Session(
        profile_name='ct_master',
        region_name=region
    )
    org_label = 'ct'    
elif root_id == "r-7w8p":
    role_name = 'OrganizationAccountAccessRole'
    session = boto3.session.Session(
        profile_name='master',
        region_name=region
    )
    org_label = 'leg'
else:
    raise ValueError(
        'Invalid Root ID. ID is either incorrect or'
        'does not belong to Globe-owned AWS Organizations'
    )
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

tgw_attachment_list = {
    (tgw['TransitGatewayId'], tgw['VpcId'], tgw['VpcOwnerId']): tgw
    for tgw in net_ec2.describe_transit_gateway_vpc_attachments(
        Filters=[
            create_filter('state', ['available'])
        ])['TransitGatewayVpcAttachments']
}
  
sts = session.client('sts')
attch_filename = (f"Attachments_to_be_removed-{org_label}_org.json")
routes_filename = (f"StaticRoutes_added-{org_label}_org.json")
import_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "transit_gateway_attachment_deploy\\"
)
attch_completeFilePath = os.path.join(import_path, attch_filename)    
routes_completeFilePath = os.path.join(import_path, routes_filename)

with open(attch_completeFilePath) as json_file:
    attachments = json.load(json_file)
# with open(routes_completeFilePath) as json_file:
#     static_routes = json.load(json_file)

for account in attachments:
    if account != session.client('sts').get_caller_identity()['Account']:
        credentials = assume_role(
            account,
            session_name='deploy-transit-gateway-attachment'
        )
        ec2 = boto3.client('ec2',
                        **credentials,
                        region_name=region
                        )
        ec2_resource = boto3.resource('ec2',
                                    **credentials,
                                    region_name=region
                                    )
    else:
        ec2 = session.client('ec2')
        ec2_resource = session.resource('ec2')
    vpc_list = ec2_resource.vpcs.all()
    for tgw_attachment in attachments[account]:
        if process_choice == "delete":
            delete_attachment(tgw_attachment)
        elif process_choice == "revert":
            attach_details = net_ec2.describe_transit_gateway_vpc_attachments(
                Filters=[
                    create_filter('transit-gateway-attachment-id', 
                                  [tgw_attachment])
                ])['TransitGatewayVpcAttachments']
            old_details = net_ec2.describe_transit_gateway_vpc_attachments(
                Filters=[
                    create_filter('transit-gateway-id', 
                                  ['tgw-04dbb41df14fdf4ea']),
                    create_filter('vpc-id',[attach_details[0]['VpcId']])
                ])['TransitGatewayVpcAttachments']
            revert_attachment(old_details, attach_details)
        else:
            logger.info("Invalid Choice")
if process_choice == "revert":
    for routeTableId in static_routes:
        for route_details in static_routes[routeTableId]:
            logger.info(f"Attemping to remove Route {route_details['Cidr']} "
                        f"in Transit Gateway Route Table {routeTableId}. . .")
            revert_tgw_route(route_details['Cidr'],routeTableId)