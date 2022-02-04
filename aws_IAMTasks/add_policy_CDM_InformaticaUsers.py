import boto3
import json
import os
import logging
import requests
import getpass
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from configparser import ConfigParser


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


def get_resource(identifier:str):
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
        return {'Arn':f"arn:aws:kms:us-west-2:896172592430:alias/*{identifier[-7:]}"}

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


def attach_policy(user_name,policy):
        try:
            user_pol = iam.get_user_policy(
                UserName=user_name,
                PolicyName=f"Informatica_CmnUtilKey_Access"
            )
            result = True
        except iam.exceptions.NoSuchEntityException:
            result = False
        if result:
            print(f"Policy already present on {user_name}")
        else:
            print(f"!!!Adding Policy to {user_name}!!!")
            iam.put_user_policy(
                UserName=user_name,
                PolicyName=f"Informatica_CmnUtilKey_Access",
                PolicyDocument=policy
            )


def create_policy():
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
                "Resource": get_resource(f"CmnUtilKeyAlias")['Arn']
            }   
        ]
    }



logger = logging.getLogger()
logger.setLevel(logging.INFO)

userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"

account_id_dict = {
    'dev': '896172592430',
    'tst': '856695471500',
    'prd': '838001389413'
}
environment_id = input("Enter environment: ").upper()
target_account_id = account_id_dict[environment_id.lower()]
target_account_name = f"cdm_{environment_id.lower()}"
org_flag = input("Is this in the CT or Legacy Org? (CT or Leg) ")
org_flag = org_flag.lower()
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

users = [user for user in iam.list_users()['Users'] if f"Informatica_{environment_id}" in user['UserName']]
policy = json.dumps(create_policy())
print(users)
for user in users:
    attach_policy(user['UserName'],policy)