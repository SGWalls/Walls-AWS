import boto3 
import json
import copy
import os
import subprocess, shlex
import logging
import inspect
import time
import pytz
import datetime
import pandas as pd


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

def create_filter(name=None, values=[]):
    return {
            "Name": name,
            "Values": values
        }

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

def check_and_update_compliance(orig_object, desired_settings):
    stack_object = copy.deepcopy(orig_object)
    user_settings = stack_object.get('UserSettings', [])
    for desired_action, desired_permission in desired_settings.items():
        for setting in user_settings:
            if setting['Action'] == desired_action:
                if setting['Permission'] != desired_permission:
                    logger.info(f"Updating {desired_action} to {desired_permission}")
                    setting['Permission'] = desired_permission
                else:
                    logger.info(f"{desired_action} is already {desired_permission}")
                break        
    return stack_object


userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\AppStream_CAS_updatestacks\\"
    )
if not os.path.exists(log_path):
    os.makedirs(log_path)
log_file_name = f"appStream-update-CAS-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
logger = create_logger('Logging',log_path,log_file_name)

session = boto3.Session(profile_name='dev_cas',region_name='us-west-2')
appstream = session.client('appstream',config=boto3.session.Config(retries={'max_attempts':10}))
user_confirm = input("Continue? (y/n): ")
if user_confirm.lower() != 'y':
    exit()

paginator = appstream.get_paginator('describe_stacks')
page_iterator = paginator.paginate()
for page in page_iterator:
    for stack in page['Stacks']:
        target_settings = check_and_update_compliance(stack, 
                            {
                                'PRINTING_TO_LOCAL_DEVICE':'ENABLED',
                                # 'FILE_DOWNLOAD':'DISABLED',
                                # 'FILE_UPLOAD':'DISABLED',
                                # 'CLIPBOARD_COPY_FROM_LOCAL_DEVICE':'DISABLED',
                                # 'CLIPBOARD_COPY_TO_LOCAL_DEVICE':'DISABLED'
                            }
                        )
        if target_settings != stack:
            logger.info(f"Updating Stack: {stack['Name']}")
            response = appstream.update_stack(
                Name=stack['Name'],
                UserSettings=target_settings['UserSettings']
            )
        # for setting in stack['UserSettings']:
        #     if {'Action': 'CLIPBOARD_COPY_FROM_LOCAL_DEVICE','Permission': 'ENABLED'} in stack['UserSettings']:
        #         logger.info(f"True for Stack: {stack['Name']}")
        #     else:
        #         logger.info(f"False for Stack: {stack['Name']}")
        #     if setting['Action'] == 'CLIPBOARD_COPY_FROM_LOCAL_DEVICE' and setting['Permission'] == 'ENABLED':
        #         logger.info(f"Updating Stack: {stack['Name']}")
        #         response = appstream.update_stack(
        #             Name=stack['Name'],
        #             UserSettings=[
        #                 {
        #                     'Action': 'FILE_DOWNLOAD',
        #                     'Permission': 'DISABLED'
        #                 },
        #                 {
        #                     'Action': 'FILE_UPLOAD',
        #                     'Permission': 'DISABLED'
        #                 },
        #                 {
        #                     'Action': 'PRINTING_TO_LOCAL_DEVICE',
        #                     'Permission': 'DISABLED'
        #                 },
        #                 {
        #                     'Action': 'CLIPBOARD_COPY_FROM_LOCAL_DEVICE',
        #                     'Permission': 'DISABLED'
        #                 },
        #                 {
        #                     'Action': 'CLIPBOARD_COPY_TO_LOCAL_DEVICE',
        #                     'Permission': 'DISABLED'
        #                 },
        #             ],
        #         )
            logger.info(f"Stack {stack['Name']} updated")
            logger.info(f"Response: {response}")
            time.sleep(1)
        else: 
            logger.info(f"Skipping Stack: {stack['Name']}")
        