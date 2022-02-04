import boto3
import json
import os
import logging
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session=boto3):
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

session = boto3.session.Session(profile_name="prd_poly",region_name="us-west-2")
test_token(session)
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
    LogGroupName=log_group_name,
    ResourceIds=[vpc_id],
    ResourceType='VPC',
    TrafficType='ALL',
    MaxAggregationInterval=60
)




