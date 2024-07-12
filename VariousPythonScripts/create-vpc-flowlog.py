import boto3
import json
import os
import logging
import subprocess, shlex
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from configparser import ConfigParser


logger = logging.getLogger()
logger.setLevel(logging.INFO)

userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"

def awscliv2_exists():
    "Return True if AWSCLIv2 is installed"
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



def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session=boto3):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            subprocess.run(shlex.split(f"aws sso login --profile {session.profile_name}"))
    return 

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

while True: 
    account_id = input("Enter the AWS Account ID of the Account where flow logs are needed: ")
    if not check_input(account_id):
        continue
    elif not check_format(account_id):
        continue
    else:
        break
# encoded_message = input("Enter the Encoded Message: ")
target_account_name = input("Enter the name of the Target Account: ")
target_account_name = target_account_name.replace(" ","_").lower()
role_name = input(
    "Name of the role you use for accessing the account (Case Sensitive):  "
)

if awscliv2_exists:
    append_profiles(aws_config_file,account_id,target_account_name,role_name)
session = boto3.session.Session(
    profile_name=target_account_name,
    region_name=region
)
test_token(session)
# session = boto3.session.Session(profile_name="prd_poly",region_name="us-west-2")
# test_token(session)
ec2 = session.client('ec2')
logs = session.client('logs')
iam = session.client('iam')
vpc_id=input("VPC ID which flow logs are needed: ")
log_group_name = f"VPC-FlowLogs/{vpc_id}-FlowLogs"
trust_policy = json.dumps({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
})
logFormat = "${account-id} ${action} ${az-id} ${bytes} ${dstaddr} ${dstport} \
${end} ${flow-direction} ${instance-id} ${interface-id} ${log-status} \
${packets} ${pkt-dst-aws-service} ${pkt-dstaddr} ${pkt-src-aws-service} \
${pkt-srcaddr} ${protocol} ${region} ${srcaddr} ${srcport} ${start} \
${sublocation-id} ${sublocation-type} ${subnet-id} ${tcp-flags} \
${traffic-path} ${type} ${version} ${vpc-id}"
policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
})
Role = iam.create_role(
        RoleName="flowlogsRole",
        AssumeRolePolicyDocument=trust_policy,
        Description='Role used for Flow Log collection'
    )['Role']
iam.put_role_policy(
    RoleName="flowlogsRole",
    PolicyName="FlowLogsAccess",
    PolicyDocument=policy
)
logs.create_log_group(
    logGroupName=log_group_name
)
ec2.create_flow_logs(
    DeliverLogsPermissionArn=Role['Arn'],
    LogFormat=logFormat,
    LogGroupName=log_group_name,
    ResourceIds=[vpc_id],
    ResourceType='VPC',
    TrafficType='ALL',
    MaxAggregationInterval=60
)





