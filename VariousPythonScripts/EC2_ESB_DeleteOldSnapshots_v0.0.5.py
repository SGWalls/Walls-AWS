import boto3
# import datetime
from datetime import datetime, timezone
import logging
import os
import sys
sys.path.insert(1,os.getcwd())
from helpers.Account import Account

ASSUMED_ROLE = "AWSControlTowerExecution" 
SNAPSHOT_AGE = 60

def check_age(sourceTime,targetAgeDays):
    current_time = datetime.now(timezone.utc)
    return (current_time - sourceTime).days > targetAgeDays

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

print("Step 1: Start . . .")
userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
    f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
        "logging\\EBSSnapShotMaintenance\\"
)
log_file_name = f"EBSSnapshotMaintenance-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

logger = create_logger('EBSSnapshotLogger',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
Aws_Account = Account('059004262227',session,'EBSSnapshotMaintenance')
# session = boto3.Session(profile_name='dev_devops',region_name='us-west-2')
# ec2 = session.client('ec2')
print("Step 2 : Setting Paginator...")
paginator = Aws_Account.client_config('ec2').get_paginator('describe_snapshots')
page_iterator = paginator.paginate(
    OwnerIds=[
        'self'
        ]
)
in_scope_snaps = []
print("Step 3 : Running Paginator and iterating Pages...")

for page in page_iterator:
    for snapshot in page['Snapshots']:
        
        # current_time = datetime.now(timezone.utc)
        if check_age(snapshot['StartTime'],SNAPSHOT_AGE):
            in_scope_snaps.append(snapshot)
print("Step 4 : Iterations complete. Printing result.")

print(len(in_scope_snaps))