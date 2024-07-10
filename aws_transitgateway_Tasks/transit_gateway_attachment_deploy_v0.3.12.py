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

DRY_RUN = False
OLD_TRANSIT_GATEWAY = 'tgw-06bb3922001900477'
NEW_TRANSIT_GATEWAY = 'tgw-0ea352e72aa369198'
CIDR_DESTINATION_EXCEPTIONS = [    
    "10.160.0.0/12",
    "10.176.0.0/16",
    "10.178.0.0/16",
    "10.179.0.0/16"
]

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "transit_gateway_attachment_deploy\\tgw_a_replacement_logs\\"
)
log_file_name = f"tgw-attachment-swap-{datetime.now().strftime('%Y%m%d')}.log"
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


def verify_ip_address(ip_address, subnet_address):
    try:
        ip_input = ipaddress.IPv4Address(ip_address)
        input_type = 'address'
    except:
        try:
            ip_input = ipaddress.IPv4Network(ip_address)
            input_type = 'network'
        except:
            raise
    response = False
    if isinstance(subnet_address,list):
        for subnet in subnet_address:
            if not response:
                response = (ip_input in ipaddress.ip_network(subnet)
                    if input_type == 'address' 
                    else ip_input.subnet_of(ipaddress.IPv4Network(subnet))
                )
    else:
        # response = ipaddress.ip_address(ip_address) in ipaddress.ip_network(subnet_address)
        response = (ip_input in ipaddress.ip_network(subnet_address)
            if input_type == 'address' 
            else ip_input.subnet_of(ipaddress.IPv4Network(subnet_address))
        )
    return response


def assume_role(account_identifier, session_name, duration=900):
    credential_response = sts_client.assume_role(
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


def account_iteration_data(id_info):
    account_name = [
        account['Name'] for account in account_list 
        if id_info in account['Id']
    ]
    tgw_filter = [
        key for key in tgw_attachment_list
        if id_info in key
        if transit_gateway_id not in key
    ]
    return account_name, tgw_filter


def get_accounts(root_identifier, parent_filter):
    target_ou_id_list = [
        ou['Id'] for ou in org.list_organizational_units_for_parent(
            ParentId=root_identifier)['OrganizationalUnits']
        if ou['Name'] in parent_filter
    ]
    target_account_list = []
    paginator = org.get_paginator('list_accounts_for_parent')
    for ou_id in target_ou_id_list:
        page_iterator = paginator.paginate(ParentId=ou_id)
        for page in page_iterator:
            target_account_list.extend(page['Accounts'])
    for account in target_account_list:
        if account['Status'] == "SUSPENDED":
            target_account_list.remove(account)
    return target_account_list


def attachment_exists_check(filterKey, filteredList, masterList, tgwId):
    try:
        result = next(x for x in masterList if 
                    x['VpcId'] == filteredList[filterKey]['VpcId'] and 
                    x['VpcOwnerId'] == filteredList[filterKey]['VpcOwnerId'] and
                    x['TransitGatewayId'] == tgwId )
    except StopIteration:
        return False
    if result:
        return True
    else:
        return False


def route_dict_gen(cidrBlock,destinationId):
    return {"Cidr":cidrBlock,"Destination":destinationId}


def add_tgw_route(destinationCidr: list, routeTableId: list, destinationId):
    for cidr in destinationCidr:
        for routeTable in routeTableId:
            try:                
                net_ec2.create_transit_gateway_route(
                    DestinationCidrBlock=cidr,
                    TransitGatewayRouteTableId=routeTable,
                    TransitGatewayAttachmentId=destinationId,
                    Blackhole=False,
                    DryRun=DRY_RUN
                )
                static_routes[routeTable].append(route_dict_gen(
                                                    cidr,
                                                    destinationId))   
                logger.info(f"Route to CIDR: {destinationCidr} with a "
                            f"destination of {destinationId}, has been added "
                            f"to Transit Gateway Route Table: {routeTable}.")             
            except ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    handle_dry_run(e)
                    static_routes[routeTable].append(route_dict_gen(
                                                    cidr,
                                                    destinationId))
                elif e.response['Error']['Code'] == 'RouteAlreadyExists':
                    logger.info(f"Route to CIDR: {destinationCidr} with a destination "
                                f"{destinationId}, Already Exists!!")
                else:
                    raise


def get_vpc_details(vpcId):
    vpc_cidrs = []
    vpc_details = ec2[account_id].describe_vpcs(VpcIds=[vpcId])['Vpcs'][0]
    # vpc_cidrs.append(vpc_details['CidrBlock'])
    if vpc_details['CidrBlockAssociationSet']:
        vpc_cidrs.extend([x['CidrBlock'] for x in 
                          vpc_details['CidrBlockAssociationSet']])
    return vpc_cidrs



def attachment_cleanup(vpc_identifier, new_target, old_attachment_id=None,
                       old_target=OLD_TRANSIT_GATEWAY):
    remove_attachment = True
    route_table_list = [
        rt for rt in ec2[account_id].describe_route_tables(Filters=[
            create_filter('route.transit-gateway-id', [old_target]),
            create_filter('vpc-id', [vpc_identifier])
        ])['RouteTables']
    ]
    for table in route_table_list:
        if (
                (table['RouteTableId'] in route_table_exclusion_list)
        ):
            logger.info(
                f"Attachment will not be removed. "
                f"{table['RouteTableId']} is on the exclusion list."
            )
            remove_attachment = False
        elif (
                (table['RouteTableId'] not in route_table_exclusion_list)
        ):
            for route in table['Routes']:
                if 'TransitGatewayId' in route.keys():
                    target_route = ec2_resource[account_id].Route(
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
    if remove_attachment:
        logger.info(
            f"END -- Adding the attachment with ID: {old_attachment_id} "
             "to the list of attachments to be removed."
        )        
        attachments_to_remove[account_id].append(old_attachment_id)
        logger.info(f"Disabling propagation of attachment with ID: "
                    f"{old_attachment_id} to Transit Gateway Route Table "
                        "with ID: tgw-rtb-07c7a524c697e84c9")
        try:
            net_ec2.disable_transit_gateway_route_table_propagation(
                TransitGatewayRouteTableId ='tgw-rtb-07c7a524c697e84c9',
                TransitGatewayAttachmentId = old_attachment_id,
                DryRun=DRY_RUN
            )
        except ClientError as e:
            if (e.response['Error']['Code'] == 
                'TransitGatewayRouteTablePropagation.NotFound'):
                logger.info("Propagation does not exist.")
            elif e.response['Error']['Code'] == 'DryRunOperation':
                handle_dry_run(e)
            else:
                raise
        delimiter()
    return 


def create_attachment(vpcid=None, subnet_identifiers=None, 
                      new_gateway_id=None,):
    try:
        delimiter('_')
        logger.info(f"Creating a new attachment for VPC: {vpcid}")
        skiptgwa = False
        try:
            new_attachment = ec2[account_id].create_transit_gateway_vpc_attachment(
                TransitGatewayId=new_gateway_id,
                VpcId=vpcid,
                SubnetIds=subnet_identifiers,
                TagSpecifications=[
                    {
                        'ResourceType': 'transit-gateway-attachment',
                        'Tags': [
                            create_tag('Name', attachment_name)
                        ]
                    }
                ],
                DryRun=DRY_RUN
            )['TransitGatewayVpcAttachment']
            # logger.debug(new_attachment) 
        except ClientError as e:
            if e.response['Error']['Code'] == 'DuplicateTransitGatewayAttachment':
                logger.info("TGWAttachment already exists")
                skiptgwa = True   
            else:
                raise
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            handle_dry_run(e)
        else:
            raise
    if not DRY_RUN and not skiptgwa:
        time.sleep(1)
        try:
            delimiter('_')
            logger.info(
                f"Adding Name tag: {attachment_name} to "
                 "Transit Gateway Attachment with ID: "
                f"{new_attachment['TransitGatewayAttachmentId']}"
            )
            net_ec2.create_tags(
                Resources=[
                    new_attachment['TransitGatewayAttachmentId']
                ],
                Tags=[
                    create_tag('Name', attachment_name)
                ],
                DryRun=DRY_RUN
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                handle_dry_run(e)
            else:
                raise

    return


logger = create_logger('tgw_a_logger')
root_id = input("Target the Legacy or Control Tower Organization? "
                "(Enter 'leg' or 'ct'): ")
# transit_gateway_id = input("Enter the NEW Transit Gateway's ID: ")
transit_gateway_id = NEW_TRANSIT_GATEWAY
target_ou_input = input(
    "Enter the names of the OU/OUs to be targetted, "
    "(Separate multiple values with a space): "
)
target_ou_list = target_ou_input.split(' ')
route_table_exlusion_input = input(
    "Enter the ID of any Route Tables to be excluded from route replacement, "
    "(Separate multiple values with a space): "
)
route_table_exclusion_list = route_table_exlusion_input.split(' ')
vpc_exclusion_input = input(
    "Enter the VpcId for any VPC to be excluded, "
    "(Separate multiple values with a space): "
)
vpc_exclusion_list = vpc_exclusion_input.split(' ')
vpc_exclusion_list.extend(
    [
        'vpc-08ccf9ad06451c082',
        'vpc-0d0c982e02b051433',
        'vpc-0416722b167ba5ad1',
        'vpc-090fcdea051c26c1e',
        'vpc-01ac5c7102063ec3d',
        'vpc-0db19012211abc0a5',
        'vpc-057346dd43a30978e'
    ]
)
region = 'us-west-2'

if root_id == "ct":
    root_id = "r-mdy1"
    role_name = 'AWSControlTowerExecution'
    session = boto3.session.Session(
        profile_name='ct_mstr',
        region_name=region
    )
    org_label = 'ct'    
elif root_id == "leg":
    root_id = "r-7w8p"
    role_name = 'OrganizationAccountAccessRole'
    session = boto3.session.Session(
        profile_name='master',
        region_name=region
    )
    org_label = 'leg'
else:
    raise ValueError(
        'Invalid Root ID. Organization target input is either incorrect or'
        'does not belong to Globe-owned AWS Organizations'
    )

org = session.client('organizations')
sts_client = session.client('sts')
net_session = boto3.session.Session(profile_name='net_svc', region_name=region)
net_ec2 = net_session.client('ec2')
net_sts_client = net_session.client('sts')
# net_credentials = assume_role(
#             '499166352453',
#             session_name='deploy-transit-gateway-attachment'
#         )
# net_ec2 = boto3.client('ec2',
#                         **net_credentials,
#                         region_name=region
#                         )
try:
    token_test = net_sts_client.get_caller_identity()
except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
    if "expired" in str(e):
        delimiter()
        logger.info(e)
        logger.info("Reinitiating SSO Login...")
        os.system(f"aws sso login --profile {net_session.profile_name}")

# account_list = get_accounts(root_id, target_ou_list)
# account_list = [{'Id': '741252614647','Arn': 'arn:aws:organizations::741252614647:account/o-tuwjxnhqr4/741252614647','Email': 'TorchmarkAWS@torchmarkcorp.com','Name': 'Torchmark AWS','Status': 'ACTIVE'},]
account_list = [{'Id': '662627786878','Arn': 'arn:aws:organizations::662627786878:account/o-w3wk3dircz/662627786878','Email': 'AWS_GlobeLife@globe.life','Name': 'Globe Life','Status': 'ACTIVE'},]
account_id_list = [identifier['Id'] for identifier in account_list]
logger.info(account_id_list)
master_list = net_ec2.describe_transit_gateway_vpc_attachments(
        Filters=[
            create_filter('state', ['available'])
        ])['TransitGatewayVpcAttachments']
tgw_attachment_list = {
    (tgw['TransitGatewayId'], tgw['VpcId'], tgw['VpcOwnerId']): tgw
    for tgw in master_list
    if tgw['VpcOwnerId'] in account_id_list
    if tgw['VpcId'] not in vpc_exclusion_list
    if tgw['TransitGatewayId'] != transit_gateway_id
}
tgw_routeTable_list = ['tgw-rtb-04214dbcfe858b011','tgw-rtb-00d12bf624f48ecc6',
                       'tgw-rtb-069ac10f7b16adde5']
static_route_destination = 'tgw-attach-02fffe2df76d38305'
ec2 = {}
ec2_resource = {}
attachments_to_remove = {}
ids_to_remove = []
static_routes ={}
for tgw_rt in tgw_routeTable_list:
    static_routes[tgw_rt] = []
logger.debug(account_id_list)
for account_id in account_id_list:
    delimiter()
    logger.debug(f"Current Iteration: {account_id}")
    account_name, tgw_filter = account_iteration_data(account_id)
    logger.debug(f"{account_name[0]}")
    logger.info(
        f"START -- Account named: {account_name[0]}, with ID: {account_id}"
    )
    attachment_name = f"{account_name[0]}-TGW"

    if account_id != session.client('sts').get_caller_identity()['Account']:
        credentials = assume_role(
            account_id,
            session_name='deploy-transit-gateway-attachment'
        )
        ec2[account_id] = boto3.client('ec2',
                        **credentials,
                        region_name=region
                        )
        ec2_resource[account_id] = boto3.resource('ec2',
                                    **credentials,
                                    region_name=region
                                    )
    else:
        ec2[account_id] = session.client('ec2')
        ec2_resource[account_id] = session.resource('ec2')
    logger.debug(tgw_filter)
    if tgw_filter:
        attachments_to_remove[account_id] = []
        for tgw in tgw_filter:
            if attachment_exists_check(tgw, tgw_attachment_list, master_list,
                                       'tgw-04dbb41df14fdf4ea'):
                logger.info(f"{account_id} already has a VPC Attachment for "
                    f"Transit Gateway: {transit_gateway_id} with vpc: "
                    f"{tgw_attachment_list[tgw]['VpcId']}")
                continue
            else:
                vpc_id = tgw_attachment_list[tgw]['VpcId']
                subnet_ids = tgw_attachment_list[tgw]['SubnetIds']
                attachment_id = tgw_attachment_list[tgw]['TransitGatewayAttachmentId']
                create_attachment(
                    vpc_id,
                    subnet_ids,
                    transit_gateway_id,
                )
    else:
        logger.info(f"Account ID: {account_id}, is being removed from the "
                     "account list."
        )
        logger.info(
            f"END -- Account :: {account_id} - {account_name[0]} :: does not " 
             "have an attachment to the Transit Gateway"
        )
        ids_to_remove.append(account_id)
        delimiter()
delimiter()
logger.info("Waiting...")
time.sleep(65)
delimiter()
account_id_list = [ id for id in account_id_list if id not in ids_to_remove ]
logger.debug(account_id_list)
for account_id in account_id_list:
    logger.debug(f"Current Iteration: {account_id}")
    account_name, tgw_filter = account_iteration_data(account_id)
    delimiter('_')
    logger.info(
        f"CONTINUING -- Account named: {account_name[0]}, with ID: "
        f"{account_id}"
    )
    logger.info(tgw_filter)
    if tgw_filter:
        for tgw in tgw_filter:
            vpc_id = tgw_attachment_list[tgw]['VpcId']
            subnet_ids = tgw_attachment_list[tgw]['SubnetIds']
            attachment_id = tgw_attachment_list[tgw]['TransitGatewayAttachmentId']
            attachment_cleanup(
                vpc_id,
                transit_gateway_id,
                attachment_id
            )
            vpc_cidr_list = get_vpc_details(vpc_id)
            logger.info(vpc_cidr_list)
            vpc_cidr_list = [cidr for cidr in vpc_cidr_list 
                if not verify_ip_address(cidr,CIDR_DESTINATION_EXCEPTIONS)]
            # add_tgw_route(vpc_cidr_list,tgw_routeTable_list,
                        # static_route_destination)
attch_filename = (f"Attachments_to_be_removed-{org_label}_org.json")
routes_filename = (f"StaticRoutes_added-{org_label}_org.json")
export_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
     "transit_gateway_attachment_deploy\\"
)
attch_completeFilePath = os.path.join(export_path, attch_filename)
routes_completeFilePath = os.path.join(export_path, routes_filename)
with open(attch_completeFilePath, "a") as f:
    f.write(
        json.dumps(attachments_to_remove, sort_keys=True, indent=4, default=str
        )
    )
with open(routes_completeFilePath, "a") as f:
    f.write(
        json.dumps(static_routes, sort_keys=True, indent=4, default=str
        )
    )

