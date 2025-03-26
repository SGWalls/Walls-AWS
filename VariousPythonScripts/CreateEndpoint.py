import boto3
import os
import logging
from configparser import ConfigParser
from PyInquirer import prompt
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


logger = logging.getLogger()
logger.setLevel(logging.INFO)
userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"


class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()

    def get_credentials(self):
        return self.assume_role('ent_setS3AccountPubBlock')

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )
    
    def get_vpc_list(self):
        """Get list of VPCs in the account"""
        ec2 = self.client_config('ec2')
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
    
    # function to return the subnets that have a Name with a given prefix which are in a given VPC
    def get_subnets(self, vpc_id, prefix):
        ec2 = self.client_config('ec2')
        response = ec2.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                },
                {
                    'Name': 'tag:Name',
                    'Values': [f"{prefix}*"]
                }
            ]
        )
        subnets = []
        az_tracker = {}
        for subnet in response['Subnets']:
            if az_tracker.get(subnet['AvailabilityZone'], 0) >= 1:
                continue
            az_tracker[subnet['AvailabilityZone']] = az_tracker.get(subnet['AvailabilityZone'], 0) + 1  
            subnets.append(subnet['SubnetId'])
        return subnets

    def get_vpc_rt(self,vpc_id):
        ec2 = self.client_config('ec2')
        response = ec2.describe_route_tables(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )
        rt_list = []
        for rt in response['RouteTables']:
            rt_list.append(rt['RouteTableId'])
        return rt_list

    def create_sg(self, group_name, vpc_id, description=""):
        ec2 = self.client_config('ec2')
        try: 
            response = ec2.create_security_group(
                Description=description,
                GroupName=group_name,
                VpcId=vpc_id,
            )
            self.create_sg_ingress_rule(response['GroupId'], ['10.0.0.0/8', '192.168.0.0/16'])
        except Exception as e:
            logger.info(e)
            logger.info("Security Group Already Exists.  Skipping Creation.") 
            if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                response = ec2.describe_security_groups(
                    Filters=[
                        {
                            'Name': 'group-name',
                            'Values': [group_name]
                        },
                        {
                            'Name': 'vpc-id',
                            'Values': [vpc_id]
                        }
                    ]
                )['SecurityGroups'][0]
        return response['GroupId']

    def create_sg_ingress_rule(self, group_id, ipRange_list):
        ec2 = self.client_config('ec2')
        ingress_permission = [
            {
                'FromPort': 443,
                'IpProtocol':'tcp',
                'IpRanges': get_ipranges(ipRange_list),
                'ToPort': 443        
            }
        ]
        response = ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=ingress_permission
        )
        return response

    def generate_vpce_kwargs(self,service_name, vpc_endpoint_type, vpc_id, subnets=None, 
                             security_groups=None, private_dns_enabled=True):
        kwargs = {
            'VpcEndpointType': vpc_endpoint_type,
            'VpcId': vpc_id,
            'ServiceName': service_name,
            'TagSpecifications': [
                {
                    'ResourceType': 'vpc-endpoint',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': get_friendly_name(service_name)
                        }
                    ]
                }
            ]
        }
        if vpc_endpoint_type == 'Gateway':
            kwargs['RouteTableIds'] = self.get_vpc_rt(vpc_id)
        elif vpc_endpoint_type == 'Interface':
            kwargs['SubnetIds'] = subnets if subnets else self.get_subnets(vpc_id, 'PVT')
            kwargs['PrivateDnsEnabled'] = private_dns_enabled
            kwargs['SecurityGroupIds'] = security_groups if security_groups else [self.create_sg(f'vpce_{get_friendly_name(service_name)}',vpc_id,f"Allows access to {get_friendly_name(service_name)} Endpoint")]
        else:
            logger.info("Invalid VPC Endpoint Type.  Must be 'Gateway' or 'Interface'")
            return None
        if security_groups:
            kwargs['SecurityGroupIds'] = security_groups
        return kwargs
    
    def create_vpce(self, service_name, vpc_endpoint_type, vpc_id, subnets, security_groups=None, 
                    private_dns_enabled=False):
        ec2 = self.client_config('ec2')
        kwargs = self.generate_vpce_kwargs(service_name, vpc_endpoint_type, vpc_id, subnets, security_groups, private_dns_enabled)
        response = ec2.create_vpc_endpoint(**kwargs)
        return response

    def select_vpc(self):
        """Display VPCs and let user select one using PyInquirer"""
        vpcs = self.get_vpc_list()        
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


def delimiter(symbol='='):
    logger.info(symbol * 120)

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

def awscliv2_exists():
    # Return True if AWSCLIv2 is installed
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )

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

def get_ipranges(ipblocks):
    ipranges=[]
    for ipblock in ipblocks:
        iprange = {
            'CidrIp': ipblock,
            'Description': f'Allows access from {ipblock}'
        }
        ipranges.append(iprange)
    return ipranges

def generate_service_name(service_name):
    if service_name.lower().startswith("com.") or service_name.lower().startswith("aws."):
        return service_name
    if service_name.lower() == "apigateway":
        return f"com.amazonaws.{region}.execute-api"
    return f"com.amazonaws.{region}.{service_name.lower()}"

def select_service():
    services = [
        's3',
        'dynamodb',
        'glue',
        'sns',
        'secretsmanager',
        'ssm',
        'apigateway',
        'sts',
        'sqs',
        'UNLISTED'
    ]

    questions = [
        {
            'type': 'list',
            'name': 'service_name',
            'message': 'Select a the service which needs an endpoint: ',
            'choices': services,
            'pageSize': 10  # Number of items visible at once
        }
    ]

    answers = prompt(questions)
    return answers['service_name']

def get_friendly_name(service_name: str) -> str:
    """
    Convert AWS service endpoint name to a friendly display name
    Example: 'com.amazonaws.us-west-2.s3' -> 'S3'
    """
    # Handle special cases first
    special_cases = {
        'execute-api': 'APIGateway',
        'email-smtp': 'SES',
        'git-codecommit': 'CodeCommitGit',
        'ecr.api': 'ECR',
        'ecr.dkr': 'ECR.Docker',
        'ecs-agent': 'ECSAgent',
        'ecs-telemetry': 'ECSTelemetry',
        'kinesis-streams': 'KinesisStreams',
        'sagemaker.api': 'SageMaker',
        'sagemaker.runtime': 'SageMakerRuntime'
    }

    # Extract the service name from the full endpoint name
    if service_name.startswith('com.amazonaws.'):
        # Split by dots and get the last part (service name)
        service = service_name.split('.')[-1]
    else:
        service = service_name

    # Check special cases first
    if service in special_cases:
        return special_cases[service]

    # Handle standard cases
    # Convert kebab-case to CamelCase
    words = service.split('-')
    friendly_name = ''.join(word.capitalize() for word in words)

    # Common abbreviations
    abbreviations = {
        'Dynamodb': 'DynamoDB',
        'Cloudwatch': 'CloudWatch',
        'Cloudformation': 'CloudFormation',
        'Apigateway': 'APIGateway',
        'Elasticloadbalancing': 'ElasticLoadBalancing',
        'Applicationautoscaling': 'ApplicationAutoScaling'
    }

    return abbreviations.get(friendly_name, friendly_name)

def generate_resource_policy(account_id):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LocalAccountRestricted",
                "Principal": "*",
                "Action": "*",
                "Effect": "Deny",
                "Resource": [
                    "*"
                ],
                "Condition": {
                    "StringNotEquals": {
                        "aws:ResourceAccount": [
                            f"{account_id}"
                        ]
                    }
                }
            }
        ]
        }



master_session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
while True: 
    account_id = input("Enter the AWS Account ID of the Account where the group is needed: ")
    if not check_input(account_id):
        continue
    elif not check_format(account_id):
        continue
    else:
        break
target_account = Account(account_id)
vpc_id = target_account.select_vpc()
subnets = target_account.get_subnets(vpc_id, 'PVT')
# service_list = [
#     's3',
#     'dynamodb',
#     'sns',
#     'secretsmanager',
#     'states',
#     'apigateway',
#     'xray'
# ]
serviceInput = select_service()
if serviceInput == 'UNLISTED':
    serviceInput = input("Enter the name of the service: ")
# for serviceInput in service_list:
print(f"Creating Endpoint for {get_friendly_name(serviceInput)}")
service = generate_service_name(serviceInput)
if service == f"com.amazonaws.{region}.s3" or service == f"com.amazonaws.{region}.dynamodb":
    vpc_endpoint_type = 'Gateway'
else:
    vpc_endpoint_type = 'Interface'

try:
    target_account.create_vpce(
        service, 
        vpc_endpoint_type= vpc_endpoint_type, 
        vpc_id = vpc_id, 
        subnets = subnets,
        private_dns_enabled=True
        )
except Exception as e:
    print(e)    


