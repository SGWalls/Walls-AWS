import boto3
from retriever import validate_sso_token, get_org_account_list


print(boto3.__version__)
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
        print(f"Account: {account['Id']}")
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
        
        try:
            access_key_list = iam.list_access_keys()['AccessKeyMetadata']
            # print(access_key_list)
            mfa_devices = iam.list_mfa_devices()['MFADevices']
            # print(mfa_devices)
            signing_cert_list = iam.list_signing_certificates()['Certificates']
            # print(signing_cert_list)
            login_profile = iam.get_login_profile()
            if login_profile:
                print(f"Deleting login profile for account: {account['Id']}")
                iam.delete_login_profile()
            if access_key_list:
                print(f"Deleting access keys for account: {account['Id']}")
                print(f"Access keys found: {access_key_list}")
                for access_key in access_key_list:
                    iam.delete_access_key(
                        AccessKeyId=access_key['AccessKeyId']
                    )
            if mfa_devices:
                print(f"Deleting MFA devices for account: {account['Id']}")
                print(f"MFA devices found: {mfa_devices}")
                for mfa_device in mfa_devices:
                    iam.deactivate_mfa_device(
                        UserName=mfa_device['UserName'],
                        SerialNumber=mfa_device['SerialNumber']
                    )
                    iam.delete_virtual_mfa_device(
                        SerialNumber=mfa_device['SerialNumber']
                    )
            if signing_cert_list:
                print(f"Deleting signing certificates for account: {account['Id']}")
                print(f"Signing certificates found: {signing_cert_list}")
                for signing_cert in signing_cert_list:
                    iam.delete_signing_certificate(
                        CertificateId=signing_cert['CertificateId']
                    )
        except iam.exceptions.NoSuchEntityException as e:
            print(f"No login profile found for account: {account['Id']}")