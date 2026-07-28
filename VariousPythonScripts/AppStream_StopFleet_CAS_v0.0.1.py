import boto3 
import json
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
            os.system(f"aws sso login --profile {session.profile_name}")
    return 

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\AppStream_CAS_StopFleets\\"
    )
if not os.path.exists(log_path):
    os.makedirs(log_path)
log_file_name = f"appStream-Stop-CAS-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
logger = create_logger('Logging',log_path,log_file_name)

session = boto3.Session(profile_name='dev_cas',region_name='us-west-2')
appstream = session.client('appstream')
user_confirm = input("Continue? (y/n): ")
if user_confirm.lower() != 'y':
    exit()
paginator = appstream.get_paginator('describe_fleets')
page_iterator = paginator.paginate()
for page in page_iterator:
    for fleet in page['Fleets']:
        if fleet['State'] == 'RUNNING':
            logger.info(f"Stopping fleet: {fleet['Name']}")
            response = appstream.stop_fleet(
                Name=fleet['Name']
            )
            logger.info(f"Response: {response}")
            time.sleep(1)