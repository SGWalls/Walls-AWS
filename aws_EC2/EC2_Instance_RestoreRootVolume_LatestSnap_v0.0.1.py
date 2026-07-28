import boto3 
import json
import os
import subprocess, shlex
import logging
import inspect
import time
import pytz
import datetime

class Account():
    def __init__(self, logger=None,account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2"):
        self.logger = logger
        self.region = region
        self.account_id = account_id
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
        self.credentials = self.get_credentials() if account_id != '741252614647' else {
            'AccessKeyId':None,
            'SecretAccessKey':None,
            'SessionToken':None
        }
        def get_caller_account(self):
            try:
                return self.session.client('sts').get_caller_identity().get('Account')
            except Exception as e:
                if "expired" in str(e):
                    delimiter()
                    logger.info(e)
                    logger.info("Reinitiating SSO Login...")
                    subprocess.run(shlex.split(
                        f"aws sso login --profile {self.session.profile_name}"
                    ))
                    return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role(self.sessionName) if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )

    def resource_config(self, service):
        return self.session.resource(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,)



class Ec2Instance():
    def __init__(self,logger=None,account_id=None, session=None, sessionName='AdminTask',
                 region="us-west-2",instance_id=None):
        self.logger = logger if logger else logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.region = region
        self.sessionName = sessionName
        self.session = session if session else boto3.Session()
        self.account_id = account_id 
        self.instance_id = instance_id
        self.credentials = self.get_credentials() if account_id != '741252614647' else {
            'AccessKeyId':None,
            'SecretAccessKey':None,
            'SessionToken':None
        }

    def get_caller_account(self):
            try:
                return self.session.client('sts').get_caller_identity().get('Account')
            except Exception as e:
                if "expired" in str(e):
                    delimiter()
                    logger.info(e)
                    logger.info("Reinitiating SSO Login...")
                    subprocess.run(shlex.split(
                        f"aws sso login --profile {self.session.profile_name}"
                    ))
                    return self.session.client('sts').get_caller_identity().get('Account')

    def get_credentials(self):
        return self.assume_role(self.sessionName) if (
            self.account_id != self.get_caller_account()) else {
                'AccessKeyId':None,
                'SecretAccessKey':None,
                'SessionToken':None
            }

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )

    def resource_config(self, service):
        return self.session.resource(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,)

    # get the root volume id for a given ec2 instance using ec2 resource
    def get_root_volume(self,instance_id):
        ec2 = self.resource_config('ec2')
        instance = ec2.Instance(instance_id)
        root_device_name= instance.root_device_name
        volumes = instance.volumes.all()
        root_volume = next((volume for volume in volumes if 
                            volume.attachments[0]['Device'] == root_device_name
                            ), None)
        return root_volume

    # retrieve the most recent snapshot for a given volume that is before 07/19/2024 00:26
    def get_most_recent_snapshot(self,volume_id):
        ec2 = self.client_config('ec2')
        snapshots = ec2.describe_snapshots(
            Filters=[
                {
                    'Name': 'volume-id',
                    'Values': [volume_id]
                }
            ]
        )['Snapshots']
        if snapshots:
            snapshots = [snapshot for snapshot in snapshots if snapshot['StartTime'] < datetime.datetime(2024, 7, 19, 5, 10, 0, tzinfo=pytz.UTC)]
            snapshots.sort(key=lambda x: x['StartTime'], reverse=True)
            return snapshots[0]['SnapshotId']
        else:
            return None
        
    # check if InstanceStatuses is 'ok' for a given instance
    def get_instance_status(self, instance_id):
        ec2 = self.client_config('ec2')
        instance_status = ec2.describe_instance_status(
            InstanceIds=[instance_id]
        )['InstanceStatuses']
        if instance_status:
            return instance_status[0]['InstanceStatus']['Details'][0]['Status']
        else:
            return False

    def repair_instance(self, instanceId):
        ec2 = self.client_config('ec2')
        try:
            self.logger.info(f"~ Attempting to repair instance {instanceId} ~")
            response = ec2.create_replace_root_volume_task(
                InstanceId=instanceId,
                SnapshotId=self.get_most_recent_snapshot(self.get_root_volume(instanceId).id)
            )
            self.logger.info(f"~ Root Volume Replace started on Instance: {instanceId} using snapshot with ID: {response['ReplaceRootVolumeTask']['SnapshotId']} ~")
            return
        except Exception as e:
            self.logger.error(e)
            return

    def heal_instance(self,instanceId):
        if self.get_instance_status(instanceId) == 'failed':
            self.repair_instance(instanceId)
            return
        else:
            self.logger.info(f"~ Instance {instanceId} is Reachable ~")
            return


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

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\EC2_RootVolRestore\\"
    )
log_file_name = f"ec2-rootvolrestore-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
logger = create_logger('Logging',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
instance_scope = input("Enter Instance ID: ")
account_id = input("Enter Account ID: ")
inst = Ec2Instance(logger=logger, instance_id=instance_scope,
                    account_id=account_id, session=session,region='us-west-2')
inst.heal_instance(instance_scope)

