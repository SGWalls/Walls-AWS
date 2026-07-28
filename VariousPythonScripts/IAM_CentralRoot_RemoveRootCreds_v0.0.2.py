import boto3
import logging
import os
import datetime
from retriever import validate_sso_token, get_org_account_list

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\IAM_CentralRootManagement\\"
    )
log_file_name = f"account-CentralRootActions-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

def delimiter(symbol='='):
    logger.info(symbol * 120)

def create_logger(logger_name,log_path,log_file_name):
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


logger = create_logger('Logging',log_path,log_file_name)
session = boto3.Session(profile_name="ct_master",region_name="us-west-2")
sts = session.client('sts',region_name='us-west-2',endpoint_url='https://sts.us-west-2.amazonaws.com')
validate_sso_token(session)
account_list = get_org_account_list(session)
# account_list = [
#     {
#         'Id':'082354424602'
#     }
# ]

for account in account_list:
    if account['Id'] != '662627786878':
        logger.info(f"Account: {account['Id']}")
        root_creds = sts.assume_root(
            TargetPrincipal=account['Id'],
            TaskPolicyArn={
                'arn': 'arn:aws:iam::aws:policy/root-task/IAMDeleteRootUserCredentials'
            }
        )['Credentials']
        iam = boto3.client(
            'iam',
            aws_access_key_id=root_creds['AccessKeyId'],
            aws_secret_access_key=root_creds['SecretAccessKey'],
            aws_session_token=root_creds['SessionToken'],
            region_name='us-west-2'
        )
        
        
        access_key_list = iam.list_access_keys()['AccessKeyMetadata']
        # logger.info(access_key_list)
        mfa_devices = iam.list_mfa_devices()['MFADevices']
        # logger.info(mfa_devices)
        signing_cert_list = iam.list_signing_certificates()['Certificates']
        # logger.info(signing_cert_list)
        try:
            login_profile = iam.get_login_profile()
        except iam.exceptions.NoSuchEntityException as e:
            logger.info(f"No login profile found for account: {account['Id']}")
            login_profile = None

        if login_profile:
            logger.info(f"Deleting login profile for account: {account['Id']}")
            iam.delete_login_profile()
        if access_key_list:
            logger.info(f"Deleting access keys for account: {account['Id']}")
            logger.info(f"Access keys found: {access_key_list}")
            for access_key in access_key_list:
                iam.delete_access_key(
                    AccessKeyId=access_key['AccessKeyId']
                )
        if mfa_devices:
            logger.info(f"Deleting MFA devices for account: {account['Id']}")
            logger.info(f"MFA devices found: {mfa_devices}")
            for mfa_device in mfa_devices:
                iam.deactivate_mfa_device(
                    SerialNumber=mfa_device['SerialNumber']
                )
                # iam.delete_virtual_mfa_device(
                #     SerialNumber=mfa_device['SerialNumber']
                # )
        if signing_cert_list:
            logger.info(f"Deleting signing certificates for account: {account['Id']}")
            logger.info(f"Signing certificates found: {signing_cert_list}")
            for signing_cert in signing_cert_list:
                iam.delete_signing_certificate(
                    CertificateId=signing_cert['CertificateId']
                )
        