import boto3
import json
import os
import logging
import requests
import getpass
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from configparser import ConfigParser

logger = logging.getLogger()
logger.setLevel(logging.INFO)

userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"

# Variables ------------------------------------------------------------------------------------------------------------
# result = "Match not found."
version = 1.0
user = os.getlogin()
SSfolderIds = {'dev': 2434, 'tst': 2435, 'prd': 2437}
SStemplateId = 6101

# Secret Server --------------------------------------------------------------------------------------------------------
sssite = 'https://ss.mgmt.tmksecure.com'
ssauthApi = '/oauth2/token'
api = sssite + '/api/v1'


class DictMap:
    def __init__(self, key_map, old_dict):
        self.key_map = key_map
        self.old_dict = old_dict

    def __getitem__(self, key):
        return (self.old_dict[self.key_map[key]] if 
                key in self.key_map else self.old_dict[key])


class User:
    def __init__(self,userName,accountId):
        self.AccountId = accountId
        self.UserName = userName
        self.create_user(self.UserName)
        self.create_key(self.UserName)
        self.policy = json.dumps(self.create_policy(
            account_id=self.AccountId,
            data_source=data_source,
            data_set=data_set
        ))
        self.attach_policy(self.policy)
        return

    def create_key(self,username):
        try:
            create_key_response = iam.create_access_key(
                UserName=username
            )['AccessKey']
            print("create_key_response: ", create_key_response)
            self.AccessKey = create_key_response['AccessKeyId']
            self.SecretAccessKey = create_key_response['SecretAccessKey']
        except iam.exceptions.LimitExceededException:
            logger.info("User already has 2 Access Keys registered. Please "
                        "remove an Access Key in order to create a new one.")
            return False
    
    def create_user(self,username):
        try:
            iam_response = iam.create_user(
            UserName=username,
            Tags=[
                {
                    'Key': 'service-request',
                    'Value': service_request if service_request else None
                },
            ]
            )
            return iam_response['User']['UserName']
        except iam.exceptions.EntityAlreadyExistsException:
            return {'UserName':username}

    def create_policy(self,account_id, data_source, data_set=None):
        bucket_name = get_bucket_name(environment_id.lower())
        prefix = (f"{data_source.replace('_','-').lower()}/"
                  f"{data_set.replace('_','-').lower()}" if data_set else
                  f"{data_source.replace('_','-').lower()}"
                 )
        if self.get_database_detail(identifier=f"dl_{data_source}_{data_set}"):
            data_catalog = f"dl_{data_source}_{data_set}"
        elif self.get_database_detail(identifier=f"dl_{data_source}"):
            data_catalog = f"dl_{data_source}"
        else:
            data_catalog = f"dl_{data_source}*"
        resource = (f"{data_source.replace('_','-').lower()}_"
                    f"{data_set.replace('_','-').lower()}" if data_set else
                    f"{data_source.replace('_','-').lower()}_")

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KMSAccess",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey"
                    ],
                    "Resource": self.get_resource(f"{resource}")['Arn']
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}/raw/{prefix}/*",
                        f"arn:aws:s3:::{bucket_name}"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "glue:*"
                    ],
                    "Resource": [
                        f"arn:aws:glue:us-west-2:{account_id}:database/{data_catalog}",
                        f"arn:aws:glue:us-west-2:{account_id}:catalog",
                        f"arn:aws:glue:us-west-2:{account_id}:table/{data_catalog}/*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "athena:GetWorkGroup",
                        "athena:GetTableMetadata",
                        "athena:StartQueryExecution",
                        "athena:GetQueryResultsStream",
                        "athena:ListDatabases",
                        "athena:GetQueryExecution",
                        "athena:GetQueryResults",
                        "athena:GetDatabase",
                        "athena:ListTableMetadata",
                        "athena:GetDataCatalog"
                    ],
                    "Resource": [
                        f"arn:aws:athena:*:{account_id}:workgroup/*",
                        f"arn:aws:athena:*:{account_id}:datacatalog/*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "athena:ListDataCatalogs",
                        "athena:ListWorkGroups"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:ListMultipartUploadParts",
                        "s3:AbortMultipartUpload",
                        "s3:CreateBucket",
                        "s3:PutObject",
                        "s3:PutBucketPublicAccessBlock"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::aws-athena-query-results-{account_id}-us-west-2/iics/*",
                        f"arn:aws:s3:::aws-athena-query-results-{account_id}-us-west-2"
                    ]
                },
                {
                    "Sid": "GlueDataCatalogKMSAccess",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey"
                    ],
                    "Resource": self.get_resource(f"CmnUtilKeyAlias")['Arn']
                }                    
            ]
        }

    def attach_policy(self,policy):
        iam.put_user_policy(
            UserName=self.UserName,
            PolicyName=f"{user_name}_Access",
            PolicyDocument=policy
        )

    def get_resource(self,identifier:str):
        client = session.client('kms')    
        if "nil_" in identifier:
            print("nil_ to nil-")
            identifier = identifier.replace('nil_','nil-')
        elif "nilpmfmast" in identifier:
            print("nilpmfmast to nil-pmfmast")
            identifier = identifier.replace('nilpmfmast','nil-pmfmast')
        print(identifier)
        try:
            return client.describe_key(
                KeyId=f"alias/{identifier}"
            )['KeyMetadata']
        except client.exceptions.NotFoundException:
            print("KMS Key not found using the provided alias,"
                " granting access to Key based on alias.")
            if "_" in identifier:
                return {'Arn':f"arn:aws:kms:us-west-2:{self.AccountId}:alias/{identifier.split('_')[0]}*"}
            else:
                return{'Arn':f"arn:aws:kms:us-west-2:{self.AccountId}:alias/{identifier}*"}

    def get_database_detail(self,identifier):
        client = session.client('athena')
        try:
            results = client.get_database(
                CatalogName='AwsDataCatalog',
                DatabaseName=f"{identifier}"
            )
            return True
        except client.exceptions.MetadataException:
            return False
            

class Secret:
    def __init__(self,token,templateId,user):
        self.secretName = f"AWS IAM User - {user.UserName}"
        self.template = self.get_template(token,templateId)
        self.secret = self.generate_secret(self.template,SSfolderId,
                                           self.secretName,user.UserName,
                                           user.AccessKey,user.SecretAccessKey,
                                           user.AccountId)
        return

    def get_template(self,token,templateId):
        headers = {
            'Authorization': 'Bearer ' + token, 
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        resp = requests.get(api + '/secret-templates/' + str(templateId), headers=headers)
        if resp.status_code not in (200, 304):
            raise Exception("Error retrieving Template. %s %s" % (resp.status_code, resp))
        return resp.json()

    def generate_item(self,keyMap,template):
        keyList = [
            "fieldDescription",
            "fieldId",
            "fieldName",
            "fileAttachmentId",
            "fileName",
            "isFile",
            "isNotes",
            "isPassword",
            "itemValue",
            "slug"
        ]
        item = remapper(keyMap,template)
        if not item['isFile']:
            item['fileAttachmentId'] = None
            item['fileName'] = None 
        item = {k:v for (k,v) in item.items() if k in keyList}
        return item

    def general_model(self):
        return {
            "name": "",
            "secretTemplateId": "",
            "folderId": "",
            "active": True,	
            "items": [],
            "launcherConnectAsSecretId": -1,
            "checkOutMinutesRemaining": 0,
            "checkedOut": False,
            "checkOutUserDisplayName": "",
            "checkOutUserId": -1,
            "isRestricted": False,
            "isOutOfSync": False,
            "outOfSyncReason": "",
            "autoChangeEnabled": False,
            "autoChangeNextPassword": None,
            "requiresApprovalForAccess": False,
            "requiresComment": False,
            "checkOutEnabled": False,
            "checkOutIntervalMinutes": -1,
            "checkOutChangePasswordEnabled": False,
            "accessRequestWorkflowMapId": -1,
            "proxyEnabled": False,
            "sessionRecordingEnabled": False,
            "restrictSshCommands": False,
            "allowOwnersUnrestrictedSshCommands": False,
            "isDoubleLock": False,
            "doubleLockId": -1,
            "enableInheritPermissions": True,
            "passwordTypeWebScriptId": -1,
            "siteId": 2,
            "enableInheritSecretPolicy": True,
            "secretPolicyId": -1,
            "lastHeartBeatStatus": "Pending",
            "secretTemplateName": ""
        }

    def generate_secret(self, template,folderId,secretName,secretUsername,
                        accessKeyId,secretKey,accountId,notes=None):
        valueSchema = {
            'device-or-service': "AWS",
            'location':accountId,
            'username':secretUsername,
            'access-key':accessKeyId,
            'secret-key':secretKey,
            'notes':notes
        }
        data = self.general_model()    
        data['name'] = secretName
        data['secretTemplateId'] = template['id']
        data['folderId'] = folderId
        data['secretTemplateName'] = template['name']
        for field in template['fields']:
            field['itemValue'] = valueSchema[field['fieldSlugName']]
            data['items'].append(self.generate_item(keyMap, field))
        return data

    def create_sssecret(self, token):
        headers = {

                'authorization': "Bearer " + token,
                'Accept-Encoding': 'gzip,deflate',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            }
        data = self.secret
        response = requests.request("POST", api + '/secrets/', headers=headers, data=json.dumps(data))
        if response.status_code >= 400:
            raise Exception('create Secret ERROR: {}'.format(response.text))
        else:
            return "Sucessfully Created Secret"


def remapper(keyMap,template: dict):
    return dict((keyMap[key], template[key]) if key in keyMap 
                 else (key, value) for key, value in template.items())


#### SS Functions ####
def getAuthToken(username, password):
    creds = {}
    creds['username'] = username
    creds['password'] = password
    creds['grant_type'] = 'password'
    uri = sssite + ssauthApi
    headers = {'Accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded'}
    resp = requests.post(uri, data=creds, headers=headers)
    if resp.status_code not in (200, 304):
        raise Exception(
            "Problems getting a token from Secret Server for %s. %s %s" % (username, resp.status_code, resp))
    return resp.json()["access_token"]


def GeneralModel():
    return {
        "name": "",
        "secretTemplateId": "",
        "folderId": "",
        "active": True,	
        "items": [],
        "launcherConnectAsSecretId": -1,
        "checkOutMinutesRemaining": 0,
        "checkedOut": False,
        "checkOutUserDisplayName": "",
        "checkOutUserId": -1,
        "isRestricted": False,
        "isOutOfSync": False,
        "outOfSyncReason": "",
        "autoChangeEnabled": False,
        "autoChangeNextPassword": None,
        "requiresApprovalForAccess": False,
        "requiresComment": False,
        "checkOutEnabled": False,
        "checkOutIntervalMinutes": -1,
        "checkOutChangePasswordEnabled": False,
        "accessRequestWorkflowMapId": -1,
        "proxyEnabled": False,
        "sessionRecordingEnabled": False,
        "restrictSshCommands": False,
        "allowOwnersUnrestrictedSshCommands": False,
        "isDoubleLock": False,
        "doubleLockId": -1,
        "enableInheritPermissions": True,
        "passwordTypeWebScriptId": -1,
        "siteId": 2,
        "enableInheritSecretPolicy": True,
        "secretPolicyId": -1,
        "lastHeartBeatStatus": "Pending",
        "secretTemplateName": ""
    }



keyMap = { 
    "secretTemplateFieldId":"fieldId",
    "description":"fieldDescription",
    "name":"fieldName",
    "fieldSlugName":"slug"
}


#### End SS Functions ####

def awscliv2_exists():
    "Return True if AWSCLIv2 is installed"
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )


def check_path(file_path):
    if not os.path.exists(os.path.dirname(file_path)):
        try:
            os.makedirs(os.path.dirname(file_path))
            return file_path
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise


def write_file(file_path, file_contents):
    with open(file_path, "w") as file_output:
        file_output.write(file_contents)


def append_profiles(filepath, account_id, account_name, filetype="config"):
    "Append/Overwrite ct_audit and legacy_audit profiles to aws config file"
    delimiter()
    print("Adding profile to your aws config file")
    config = ConfigParser()
    config.read(filepath)
    if filetype.lower() == "config":
        profile = "profile "
    if filetype.lower() == "credentials":
        profile = ""
    if org_flag == "ct":
        config[f"{profile}{account_name}"] = dict(
            sso_start_url = "https://globeaws.awsapps.com/start",
            sso_region = region,
            sso_account_id = account_id,
            sso_role_name = "AWSAdministratorAccess",
            region = region,
            ca_bundle = "C:\\Program Files\\Amazon\AWSCLIV2\\nskp_config\\netskope-cert-bundle.pem",
            output = "json",
        )
    elif org_flag == "leg":
            config[f"{profile}{account_name}"] = dict(
            source_profile = "master",
            role_arn = f'arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole',
            region = region,
            ca_bundle = "C:\\Program Files\\Amazon\AWSCLIV2\\nskp_config\\netskope-cert-bundle.pem",
            output = "json",
        )
    with open(filepath, "w") as configfile:
        config.write(configfile)
        delimiter()
    print(f"Added profile {profile}{account_name} to your aws config file")


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


def assume_role(account_id, session_name, duration=900):        
    response = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/AWSControlTowerExecution",
        RoleSessionName=session_name,
        DurationSeconds=duration
    )
    return response['Credentials']


def client_config(creds,service,region='us-west-2'):
    response = session.client(
        aws_access_key_id = creds['AccessKeyId'],
        aws_secret_access_key = creds['SecretAccessKey'],
        aws_session_token = creds['SessionToken'],
        region_name = region,
        service_name = service
    )
    return response


def delimiter(symbol='='):
    logger.info(symbol * 120)


# def get_resource(identifier:str):
#     client = session.client('kms')    
#     if "nil_" in identifier:
#         print("nil_ to nil-")
#         identifier = identifier.replace('nil_','nil-')
#     elif "nilpmfmast" in identifier:
#         print("nilpmfmast to nil-pmfmast")
#         identifier = identifier.replace('nilpmfmast','nil-pmfmast')
#     print(identifier)
#     try:
#         return client.describe_key(
#             KeyId=f"alias/{identifier}"
#         )['KeyMetadata']
#     except client.exceptions.NotFoundException:
#         print("KMS Key not found using the provided alias,"
#               " granting access to Key based on alias.")
#         if "_" in identifier:
#             return {'Arn':f"arn:aws:kms:us-west-2:896172592430:alias/{identifier.split('_')[0]}*"}
#         else:
#             return{'Arn':f"arn:aws:kms:us-west-2:896172592430:alias/{identifier}*"}

def get_bucket_name(env:str):
    if env == "dev":
        return 'tmk-cdm-data'
    elif env in ["test","tst"]:
        return 'tmk-cdm-test-data'
    elif env in ["prod","prd"]:
        return 'tmk-cdm-prd-data'
    else:
        print("environment not detected")
        return None

# def create_policy(account_id, company_id, catalog_name):
#     resource_name = f"dl_{company_id}_mainframe_{catalog_name}"
#     return {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Sid": "KMSAccess",
#                 "Effect": "Allow",
#                 "Action": [
#                     "kms:Encrypt",
#                     "kms:Decrypt",
#                     "kms:ReEncrypt*",
#                     "kms:GenerateDataKey*",
#                     "kms:DescribeKey"
#                 ],
#                 "Resource": get_resource(f"{company_id.lower()}-mainframe_{catalog_name.replace('_','-').lower()}")['Arn']
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "s3:PutObject",
#                     "s3:GetObject",
#                     "s3:DeleteObject",
#                     "s3:ListBucket"
#                 ],
#                 "Resource": [
#                     f"arn:aws:s3:::tmk-cdm-data/raw/{company_id}-mainframe/{catalog_name}/*",
#                     "arn:aws:s3:::tmk-cdm-data"
#                 ]
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "glue:*"
#                 ],
#                 "Resource": [
#                     f"arn:aws:glue:us-west-2:{account_id}:database/{resource_name}",
#                     f"arn:aws:glue:us-west-2:{account_id}:catalog",
#                     f"arn:aws:glue:us-west-2:{account_id}:table/{resource_name}/*"
#                 ]
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "athena:GetWorkGroup",
#                     "athena:GetTableMetadata",
#                     "athena:StartQueryExecution",
#                     "athena:GetQueryResultsStream",
#                     "athena:ListDatabases",
#                     "athena:GetQueryExecution",
#                     "athena:GetQueryResults",
#                     "athena:GetDatabase",
#                     "athena:ListTableMetadata",
#                     "athena:GetDataCatalog"
#                 ],
#                 "Resource": [
#                     f"arn:aws:athena:*:{account_id}:workgroup/*",
#                     f"arn:aws:athena:*:{account_id}:datacatalog/*"
#                 ]
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "athena:ListDataCatalogs",
#                     "athena:ListWorkGroups"
#                 ],
#                 "Resource": "*"
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "s3:GetBucketLocation",
#                     "s3:GetObject",
#                     "s3:ListBucket",
#                     "s3:ListBucketMultipartUploads",
#                     "s3:ListMultipartUploadParts",
#                     "s3:AbortMultipartUpload",
#                     "s3:CreateBucket",
#                     "s3:PutObject",
#                     "s3:PutBucketPublicAccessBlock"
#                 ],
#                 "Resource": [
#                     f"arn:aws:s3:::aws-athena-query-results-{account_id}-us-west-2/iics/*",
#                     f"arn:aws:s3:::aws-athena-query-results-{account_id}-us-west-2"
#                 ]
#             }    
#         ]
#     }


userprofile = os.environ["USERPROFILE"]
account_id_dict = {
    'dev': '896172592430',
    'tst': '856695471500',
    'prd': '838001389413'
}
# target_account_id = input("Enter the Target Account ID: ")
# target_account_name = input("Enter a name for the Target Account: ")
# target_account_name = target_account_name.replace(" ","_").lower()
service_request = input("What is the Request ID for this request? ")
environment_id = input("Enter environment: ").upper()
SSfolderId = SSfolderIds[environment_id.lower()]
target_account_id = account_id_dict[environment_id.lower()]
target_account_name = f"cdm_{environment_id.lower()}"
username = 'tmk\sgwalls' #Full Service Accoutn Name Here (Including Domain)
password = getpass.getpass('Please Enter Your Password: ') #Password for service account Username
org_flag = input("Is this in the CT or Legacy Org? (CT or Leg) ")
org_flag = org_flag.lower()
print("Attempting authentication for %s..." % username)
token = getAuthToken(username,password)
print("Authentication successful.\n")
catalogs = {
	'internal_files': [
		'',
        'refinedusps_delstat'
	],
    'external_datasets':[
        ''
    ]
}

region = "us-west-2"
if awscliv2_exists:
    append_profiles(aws_config_file,target_account_id,target_account_name)
session = boto3.session.Session(
    profile_name=target_account_name,
    region_name=region
)
sts = session.client("sts")
test_token(session)

iam = session.client('iam')
sm = session.client('secretsmanager')

for k,v in catalogs.items():
    for item in v:
        data_source = k if k else None
        data_set = item if item else None       
        user_name = (f"Informatica_{environment_id}_{data_source}_{data_set}"
                     if data_set else 
                     f"Informatica_{environment_id}_{data_source}")
        secretName = f"AWS IAM User - {user_name}"

        print("Creating IAM user")
        userObj = User(user_name,target_account_id)
        print("AccessKey: " + userObj.AccessKey + "\nSecretAccessKey: " + userObj.SecretAccessKey)
        print("Creating Secret and publishing to Vault")
        secretObj = Secret(token,SStemplateId,userObj)
        secret_response = secretObj.create_sssecret(token)

        print(secret_response)