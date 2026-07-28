import boto3
import pprint
from retriever import validate_sso_token

update_param_keys = [
    "UserPoolId",
    "Policies",
    "DeletionProtection",
    "LambdaConfig",
    "AutoVerifiedAttributes",
    "SmsVerificationMessage",
    "EmailVerificationMessage",
    "EmailVerificationSubject",
    "VerificationMessageTemplate",
    "SmsAuthenticationMessage",
    "UserAttributeUpdateSettings",
    "MfaConfiguration",
    "DeviceConfiguration",
    "EmailConfiguration",
    "SmsConfiguration",
    "UserPoolTags",
    "AdminCreateUserConfig",
    "UserPoolAddOns",
    "AccountRecoverySetting",
    "PoolName",
    "UserPoolTier"
]

session = boto3.Session(profile_name='id_svcs',region_name='us-west-2')
validate_sso_token(session)
cognito = session.client('cognito-idp')
pool_details = cognito.describe_user_pool(UserPoolId='us-west-2_RTdqDrSuA')['UserPool']

# Field mapping from describe_user_pool to update_user_pool
field_mapping = {
    "UserPoolId": "Id",
    "PoolName": "Name",
    "Policies": "Policies",
    "DeletionProtection": "DeletionProtection",
    "AutoVerifiedAttributes": "AutoVerifiedAttributes",
    "SmsVerificationMessage": "SmsVerificationMessage",
    "EmailVerificationMessage": "EmailVerificationMessage",
    "EmailVerificationSubject": "EmailVerificationSubject",
    "VerificationMessageTemplate": "VerificationMessageTemplate",
    "SmsAuthenticationMessage": "SmsAuthenticationMessage",
    "UserAttributeUpdateSettings": "UserAttributeUpdateSettings",
    "MfaConfiguration": "MfaConfiguration",
    "DeviceConfiguration": "DeviceConfiguration",
    "EmailConfiguration": "EmailConfiguration",
    "SmsConfiguration": "SmsConfiguration",
    "UserPoolTags": "UserPoolTags",
    "AdminCreateUserConfig": "AdminCreateUserConfig",
    "UserPoolAddOns": "UserPoolAddOns",
    "AccountRecoverySetting": "AccountRecoverySetting",
    "UserPoolTier": "UserPoolTier"
}

# Build update params from existing config
update_params = {k: pool_details.get(v) for k, v in field_mapping.items() if pool_details.get(v) is not None}
# Update lambda config with new PostAuthentication ARN
if "LambdaConfig" in pool_details:
    lambda_config = pool_details["LambdaConfig"].copy()
    lambda_config["PostAuthentication"] = "arn:aws:lambda:us-west-2:229844166211:function:WSBDevPostAuth"
    update_params["LambdaConfig"] = lambda_config

pprint(update_params, width=100, sort_dicts=False)
