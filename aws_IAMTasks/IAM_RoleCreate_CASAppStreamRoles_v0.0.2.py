import boto3 
import json
import copy
import os
import subprocess, shlex
import logging
import time
import datetime
from aws_cdk import aws_iam as iam

location_list = [
    # 'CAS_FP_SAML_POC_1',
    'CAS_FP_15',
    # 'CAS_FP_1D',
    # 'CAS_FP_1G',
    # 'CAS_FP_1M',
    # 'CAS_FP_1R',
    # 'CAS_FP_1S',
    # 'CAS_FP_1V',
    # 'CAS_FP_1Y',
    # 'CAS_FP_25',
    # 'CAS_FP_29',
    # 'CAS_FP_2T',
    # 'CAS_FP_2U',
    # 'CAS_FP_31',
    # 'CAS_FP_3B',
    # 'CAS_FP_3F',
    # 'CAS_FP_3H',
    # 'CAS_FP_3J',
    # 'CAS_FP_3K',
    # 'CAS_FP_3P',
    # 'CAS_FP_3V',
    # 'CAS_FP_41',
    # 'CAS_FP_46',
    # 'CAS_FP_47',
    # 'CAS_FP_48',
    # 'CAS_FP_4F',
    # 'CAS_FP_4K',
    # 'CAS_FP_4W',
    # 'CAS_FP_51',
    # 'CAS_FP_54',
    # 'CAS_FP_5A',
    # 'CAS_FP_5F',
    # 'CAS_FP_5H',
    # 'CAS_FP_5J',
    # 'CAS_FP_5T',
    # 'CAS_FP_64',
    # 'CAS_FP_65',
    # 'CAS_FP_66',
    # 'CAS_FP_67',
    # 'CAS_FP_6C',
    # 'CAS_FP_6L',
    # 'CAS_FP_6R',
    # 'CAS_FP_6S',
    # 'CAS_FP_73',
    # 'CAS_FP_79',
    # 'CAS_FP_7G',
    # 'CAS_FP_7H',
    # 'CAS_FP_7P',
    # 'CAS_FP_7X',
    # 'CAS_FP_82',
    # 'CAS_FP_87',
    # 'CAS_FP_8B',
    # 'CAS_FP_8L',
    # 'CAS_FP_8R',
    # 'CAS_FP_96',
    # 'CAS_FP_97',
    # 'CAS_FP_9A',
    # 'CAS_FP_9C',
    # 'CAS_FP_9J',
    # 'CAS_FP_A7',
    # 'CAS_FP_A9',
    # 'CAS_FP_ADollar',
    # 'CAS_FP_AJ',
    # 'CAS_FP_AN',
    # 'CAS_FP_AW',
    # 'CAS_FP_AutoSync',
    # 'CAS_FP_AutoSyncTest22App',
    # 'CAS_FP_BB',
    # 'CAS_FP_BH',
    # 'CAS_FP_BY',
    # 'CAS_FP_CA',
    # 'CAS_FP_CB',
    # 'CAS_FP_CJ',
    # 'CAS_FP_CK',
    # 'CAS_FP_CS',
    # 'CAS_FP_CT',
    # 'CAS_FP_CV',
    # 'CAS_FP_CY',
    # 'CAS_FP_D6',
    # 'CAS_FP_DQ',
    # 'CAS_FP_DollarJ',
    # 'CAS_FP_E4',
    # 'CAS_FP_E9',
    # 'CAS_FP_EY',
    # 'CAS_FP_FF',
    # 'CAS_FP_FH',
    # 'CAS_FP_FI',
    # 'CAS_FP_FL',
    # 'CAS_FP_FR',
    # 'CAS_FP_FW',
    # 'CAS_FP_G3',
    # 'CAS_FP_H6',
    # 'CAS_FP_HZ',
    # 'CAS_FP_JJ',
    # 'CAS_FP_KR',
    # 'CAS_FP_KT',
    # 'CAS_FP_LE',
    # 'CAS_FP_LV',
    # 'CAS_FP_MDollar',
    # 'CAS_FP_MR',
    # 'CAS_FP_N6',
    # 'CAS_FP_N8',
    # 'CAS_FP_NA',
    # 'CAS_FP_NB',
    # 'CAS_FP_ND',
    # 'CAS_FP_NI',
    # 'CAS_FP_NK',
    # 'CAS_FP_NPND',
    # 'CAS_FP_NU',
    # 'CAS_FP_NW',
    # 'CAS_FP_OC',
    # 'CAS_FP_OH',
    # 'CAS_FP_PE',
    # 'CAS_FP_PW',
    # 'CAS_FP_Pnd3',
    # 'CAS_FP_QR',
    # 'CAS_FP_QV',
    # 'CAS_FP_R9',
    # 'CAS_FP_RDOLLAR',
    # 'CAS_FP_RX',
    # 'CAS_FP_SAML_POC_v2',
    # 'CAS_FP_SAML_POC_v3',
    # 'CAS_FP_SAML_POC_v4',
    # 'CAS_FP_SUPPORT',
    # 'CAS_FP_TI',
    # 'CAS_FP_TW',
    # 'CAS_FP_V3',
    # 'CAS_FP_V4',
    # 'CAS_FP_V8',
    # 'CAS_FP_V9',
    # 'CAS_FP_W3',
    # 'CAS_FP_XG',
    # 'CAS_FP_Y6',
    # 'CAS_FP_Z6',
    # 'CAS_FP_ZC',
    # 'CAS_FP_ZL',
    # 'CAS_FP_ZW',
    # 'CAS_SUPPORT_Desktop',
    # 'CAS_SUPPORT_OrigVpc',
    # 'CAS_SUPPORT_OrigVpc2'
]

def delimiter(symbol='='):
    logger.info(symbol * 120)

def handle_dry_run(error):
    logger.info(f"Operation: {error.operation_name}")
    logger.info(f"{error.response['Error']['Message']}")

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

def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except Exception as e:
        if "expired" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            subprocess.run(shlex.split(f"aws sso login --profile {session.profile_name}"))
    return 

def generate_condition(operator, key, value):
    return {
        operator: {
            key: value
        }
    }

def create_statement(actions: list, effect, resources = None, principal=None, conditions=None):
    statement = {
        "Effect": effect,
        "Action": []
    }
    if not isinstance(actions, list):
        actions = [actions] 
    for action in actions:
        statement["Action"].append(action)
    if resources:
        if not isinstance(resources, list):
            resources = [resources]
        statement["Resource"] = resources
    if principal:
        statement["Principal"] = principal
    if conditions:
        statement["Condition"] = conditions
    return statement  

def generate_resource(service, region, accountId, resource):
    return f"arn:aws:{service}:{region}:{accountId}:{resource}" 

def create_policy_document(statementList):
    policy_document = {
        "Version": "2012-10-17",
        "Statement": statementList
    }
    return json.dumps(policy_document)


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\AppStream_CAS_createFleetRoles\\"
    )
if not os.path.exists(log_path):
    os.makedirs(log_path)
log_file_name = f"appStream-update-CAS-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"

logger = create_logger('Logging',log_path,log_file_name)
# session = boto3.Session(profile_name='prd_cas',region_name='us-west-2')
# iam = session.client('iam')
# test_token(session)
# waiter = iam.get_waiter('role_exists')
parameter_list = [
    'cas_sa_password',
    'cas_sa_username',
    'cas_unc_path'
]
for location in location_list: 
    location_partition = '_'.join(location.split('_')[2:])
    resource_list = [
        generate_resource('ssm','us-west-2','827354439487',
            f'locations/{location_partition}/{parameter}'
            ) for parameter in parameter_list
    ]
    # logger.info(resource_list[0])
    iam_role_params = {
        "RoleName": f'AppStream_{location}_FleetRole',
        "AssumeRolePolicyDocument": create_policy_document(
            create_statement(
                actions='sts:AssumeRole',
                effect='Allow',
                principal={
                    "Service": "appstream.amazonaws.com"
                }
            )
        ),
        "Description": f'Access Role used for AppStream Fleet {location}'
    }
    iam_role_details = {}
    iam_role_details['Role'] = {}
    iam_role_details['Role']['RoleName'] = iam_role_params["RoleName"]
    # try:
    #     iam_role_details = iam.create_role(**iam_role_params) 
    #     waiter.wait(RoleName=iam_role_details['Role']["RoleName"])  
    # except iam.exceptions.EntityAlreadyExistsException:
    #     logger.info(f"Role {iam_role_params['RoleName']} already exists.")
    #     continue
    iam_policy_params = {
        "PolicyName": f'AppStream_{location}_FleetPolicy',
        "PolicyDocument": create_policy_document(
            create_statement(
                actions=['ssm:GetParameter'],
                effect='Allow',
                resources=resource_list
            )
        ),
        "RoleName": iam_role_details["Role"]["RoleName"]
    }
    logger.info(iam_role_params)
    logger.info(iam_policy_params)
    # iam.put_role_policy(**iam_policy_params)

    # iam_role_detail = iam.create_role(
    #     RoleName=f'AppStream_CAS_{location}_FleetRole',
    #     AssumeRolePolicyDocument=create_policy_document(
    #         create_statement(
    #             actions='sts:AssumeRole',
    #             effect='Allow',
    #             principal={
    #                 "Service": "appstream.amazonaws.com"
    #             }
    #         )
    #     ),
    #     Description=f'Access Role used for AppStream Fleet {location}'
    # )
    

