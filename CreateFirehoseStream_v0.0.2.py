import boto3
import json


session = boto3.session.Session(profile_name='net_sec',region_name='us-west-2')
m_session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
org = m_session.client('organizations')
firehose = session.client('firehose')
sts = session.client('sts')
logs = session.client('logs')
iam = session.resource('iam')

iam_assume_role_doc = {
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "FirehoseAssumeRole",
			"Effect": "Allow",
			"Principal": {
				"Service": "firehose.amazonaws.com"
			},
			"Action": "sts:AssumeRole"
		}
	]
}
iam_policy_doc = {
    "Version": "2012-10-17",  
    "Statement":
    [    
        {      
            "Effect": "Allow",      
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
				"s3:PutObjectAcl"
            ],      
            "Resource": [        
                bucketArn,
                f"{bucketArn}/*"		    
            ]    
        },        
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:DescribeStream",
                "kinesis:GetShardIterator",
                "kinesis:GetRecords",
                "kinesis:ListShards"
            ],
            "Resource": ken_arn
        },
        {
           "Effect": "Allow",
           "Action": [
               "kms:Decrypt",
               "kms:GenerateDataKey"
           ],
           "Resource": [
               kmsKeyArn           
           ],
           "Condition": {
               "StringEquals": {
                   "kms:ViaService": "s3.us-west-2.amazonaws.com"
               },
               "StringLike": {
                   "kms:EncryptionContext:aws:s3:arn": f"{bucketArn}/*"
               }
           }
        },
        {
           "Effect": "Allow",
           "Action": [
               "logs:PutLogEvents"
           ],
           "Resource": [
               f"arn:aws:logs:us-west-2:738683365990:log-group:{log_group_name}:log-stream:*"
           ]
        }
    ]
}


def get_account_information():
    accountDetails = {}
    accountDetails['Id'] = sts.get_caller_identity()['Account']
    orgDetails = org.describe_account(AccountId=accountDetails['Id'])
    accountDetails['Name'] = orgDetails.get('Account').get('Name')
    return accountDetails

def check_log_group(group_name):
    if logs.describe_log_groups(logGroupNamePrefix=group_name)['logGroups']:
        return group_name
    else:
        response = logs.create_log_group(
            logGroupName=group_name
        )
        return group_name

def check_log_stream(group_name,stream_name):
    if logs.describe_log_streams(
        logGroupName=group_name, 
        logStreamNamePrefix=stream_name
    )['logStreams']:
        return stream_name
    else: 
        response = logs.create_log_stream(
            logGroupName = group_name,
            logStreamName = stream_name
        )
        return stream_name

def create_iam_role(role_name,assume_role_doc,role_policy_doc):
    iam = session.client('iam')
    role_response = iam.create_role(
        RoleName = role_name,
        AssumeRolePolicyDocument=json.load(assume_role_doc),
        Description = "Access Delegated for Enterprise WAF Logging",
        Tags = [
            {
                'Key': 'enterprise-managed',
                'Value': 'true'
            }
        ]
    )
    iam.put_role_policy(
        RoleName = role_name,
        PolicyName = f"{role_name}-Policy",
        PolicyDocument = json.load(role_policy_doc)
    )
    return role_response


def check_role(role_name,accountId):
    role = iam.Role(role_name)
    try:
        roleArn = role.arn
    except:
        role_exists = False  
    else:
        role_exists = True       

    if role_exists:
        return roleArn
    else:
        response = create_iam_role(
            role_name,
            iam_assume_role_doc,
            iam_policy_doc
        )            
        roleArn = f"arn:aws:iam::{accountId}:role/{role_name}"            
        return roleArn


account = get_account_information()
roleArn = f"arn:aws:iam::{account['Id']}:role/EnterpriseWAFLogging"
roleName = "EnterpriseWAFLogging"
kmsKeyArn = 'arn:aws:kms:us-west-2:113204598149:key/b4cedbed-8668-4b98-a43e-349b29048301'
bucketArn = 'arn:aws:s3:::enterprise-waf-logs-113204598149-us-west-2'
s3prefix = f"enterprise-FMS-{account['Id']}-{account['Name']}-waf"
log_group_name = f"/aws/kinesisfirehose/aws-waf-logs-{account['Name']}"
log_stream_name = "S3Delivery"
del_stream_name = f"aws-waf-logs-{account['Name']}"
ken_arn = f"arn:aws:kinesis:us-west-2:{account['Id']}:stream/{del_stream_name}"


firehose.create_delivery_stream(
    DeliveryStreamName = del_stream_name,
    DeliveryStreamType = 'DirectPut',
    ExtendedS3DestinationConfiguration = {
        'RoleARN': check_role(roleName,account['Id']),
        'BucketARN': bucketArn,
        'Prefix': f"{s3prefix}-logs",
        'ErrorOutputPrefix': f"{s3prefix}-errors",
        'BufferingHints': {
            'SizeInMBs': 10,
            'IntervalInSeconds': 300
        },
        'CompressionFormat': 'UNCOMPRESSED',
        'EncryptionConfiguration': {
            'KMSEncryptionConfig': {
                'AWSKMSKeyARN': kmsKeyArn
            }
        },
        'CloudWatchLoggingOptions': {
            'Enabled': True,
            'LogGroupName': check_log_group(log_group_name),
            'LogStreamName': check_log_stream(log_group_name,log_stream_name)
        },
        'ProcessingConfiguration': {
            'Enabled': False
        },
        'S3BackupMode': 'Disabled',
        'DataFormatConversionConfiguration': {
            'Enabled': False
        }
    }
)
