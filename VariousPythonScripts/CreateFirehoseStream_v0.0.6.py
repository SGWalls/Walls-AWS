import boto3
import json
import re


session = boto3.session.Session(profile_name='itsec_prod',region_name='us-west-2')
m_session = boto3.session.Session(profile_name='master',region_name='us-west-2')
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
def create_policy_doc(bucketArn,ken_arn,log_group_name):
    return {
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
                "kms:Encrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": [
                kmsKeyArn           
            ]
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
    try:
        logs.create_log_group(
            logGroupName=group_name
        )
    except logs.exceptions.ResourceAlreadyExistsException:
        print("Log group already exists.")
    return group_name

def check_log_stream(group_name,stream_name):
    try:               
        logs.create_log_stream(
            logGroupName = group_name,
            logStreamName = stream_name
        )
        print("created log stream...")
    except logs.exceptions.ResourceAlreadyExistsException:
        print("Log stream already exists.")
    return stream_name

def create_iam_role(role_name,assume_role_doc,role_policy_doc):
    iam = session.client('iam')
    try:
        role_response = iam.create_role(
            RoleName = role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_doc),
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
            PolicyDocument = json.dumps(role_policy_doc)
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print("Role Already Exists")
        role_response = {'Role':{'Arn': f"arn:aws:iam::{get_account_information()['Id']}:role/{role_name}"}}
    try:
        iam.get_role_policy(RoleName=role_name,PolicyName=f"{role_name}-Policy")
    except iam.exceptions.NoSuchEntityException:
        print("Role does not include Policy.  Adding.")
        iam.put_role_policy(
            RoleName = role_name,
            PolicyName = f"{role_name}-Policy",
            PolicyDocument = json.dumps(create_policy_doc(bucketArn,
                                                            ken_arn,
                                                            log_group_name))
        )
    return role_response.get('Role').get('Arn')


# def check_role(role_name,accountId):
#     iam = session.client('iam')
#     # role = iam.Role(role_name)
#     try:
#        roleArn = iam.get_role(RoleName=role_name)['Role']['Arn']
#     except iam.exceptions.NoSuchEntityException:
#         role_exists = False  
#     else:
#         role_exists = True 
#         try:
#             iam.get_role_policy(RoleName=role_name,PolicyName=f"{role_name}-Policy")
#         except iam.exceptions.NoSuchEntityException:
#             iam.put_role_policy(
#                 RoleName = role_name,
#                 PolicyName = f"{role_name}-Policy",
#                 PolicyDocument = json.dumps(create_policy_doc(bucketArn,
#                                                               ken_arn,
#                                                               log_group_name))
#             )
#     if role_exists:
#         return roleArn
#     else:
#         response = create_iam_role(
#             role_name,
#             iam_assume_role_doc,
#             create_policy_doc(bucketArn,ken_arn,log_group_name)
#         )            
#         roleArn = f"arn:aws:iam::{accountId}:role/{role_name}"            
#         return response.get('Role').get('Arn')


def sanitize(name, space_allowed=False, replace_with_character='_'):
    # This function will replace any character other than [a-zA-Z0-9._-] with '_'
    if space_allowed:
        sanitized_name = re.sub(r'([^\sa-zA-Z0-9._-])', replace_with_character, name)
    else:
        sanitized_name = re.sub(r'([^a-zA-Z0-9._-])', replace_with_character, name)
    return sanitized_name


account = get_account_information()
accountName = sanitize(account['Name'])
roleArn = f"arn:aws:iam::{account['Id']}:role/EnterpriseWAFLogging"
roleName = "EnterpriseWAFLogging"
kmsKeyArn = 'arn:aws:kms:us-west-2:113204598149:key/b4cedbed-8668-4b98-a43e-349b29048301'
bucketArn = 'arn:aws:s3:::enterprise-waf-logs-113204598149-us-west-2'
s3prefix = f"enterprise-FMS-{account['Id']}-{accountName}-waf"
log_group_name = f"/aws/kinesisfirehose/aws-waf-logs-{accountName}"
log_stream_name = "S3Delivery"
del_stream_name = f"aws-waf-logs-{accountName}"
ken_arn = f"arn:aws:kinesis:us-west-2:{account['Id']}:stream/{del_stream_name}"

try:
    firehose.create_delivery_stream(
        DeliveryStreamName = del_stream_name,
        DeliveryStreamType = 'DirectPut',
        ExtendedS3DestinationConfiguration = {
            'RoleARN': create_iam_role(roleName,iam_assume_role_doc,
                                    create_policy_doc(bucketArn,
                                            ken_arn,
                                            log_group_name)),
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
except firehose.exceptions.ResourceInUseException:
    print("Delivery Stream already exists.")
