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

DRY_RUN = True


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
            if instance_status[0]['InstanceState']['Name'] == 'running':
                return instance_status[0]['InstanceStatus']['Details'][0]['Status']
        else:
            return False

    def repair_instance(self, instanceId):
        ec2 = self.client_config('ec2')
        root_volume = self.get_root_volume(instanceId).id
        snapshot_id = self.get_most_recent_snapshot(root_volume)
        if snapshot_id and not ec2.describe_replace_root_volume_tasks(
                Filters=[create_filter('instance-id',[instanceId])])['ReplaceRootVolumeTasks']:
            try:
                self.logger.info(f"~ Attempting to repair instance {instanceId} ~")
                response = ec2.create_replace_root_volume_task(
                    InstanceId=instanceId,
                    SnapshotId=snapshot_id,
                    DryRun=DRY_RUN
                )
                self.logger.info(f"~ Root Volume Replace started on Instance: {instanceId} using snapshot with ID: {response['ReplaceRootVolumeTask']['SnapshotId']} ~")
                return pd.DataFrame([data_dict_format(
                    accountId=self.account_id,
                    instanceId=instanceId,
                    originalVolume=root_volume,
                    snapshotID=snapshot_id
                )])
            except Exception as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    handle_dry_run(e)
                else:
                    self.logger.error(e)
                return []
        else:
            self.logger.info(f"!!! No Snapshot for volume: {root_volume} on instance: {instanceId }!!!")
            return pd.DataFrame([data_dict_format(
                    accountId=self.account_id,
                    instanceId=instanceId,
                    originalVolume=root_volume,
                    snapshotID="No Snapshot Available"
                )]) if not snapshot_id else []

    def heal_instance(self,instanceId):
        if self.get_instance_status(instanceId) == 'failed':
            return self.repair_instance(instanceId)
        else:
            self.logger.info(f"~ Instance {instanceId} is Reachable ~")
            return []


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

def data_dict_format(accountId,instanceId, originalVolume, snapshotID):
    return {
        'Account ID' : accountId,
        'Instance ID' : instanceId,
        'Original Root Volume' : originalVolume,
        'Snapshot ID' : snapshotID
    }

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\EC2_RootVolRestore\\"
    )
if not os.path.exists(log_path):
    os.makedirs(log_path)
log_file_name = f"ec2-rootvolrestore-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
file_location = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\exports\\EC2_RootVolRestore\\"
    )
if not os.path.exists(file_location):
    os.makedirs(file_location)
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = os.path.join(file_location, f'all_hosted_zones_{timestamp}.csv')
logger = create_logger('Logging',log_path,log_file_name)
session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
# instance_scope = input("Enter Instance ID: ")
account_id = input("Enter Account ID: ")
all_dfs = []

accnt = Account(logger=logger, account_id=account_id, session=session)
instance_list = accnt.resource_config('ec2').instances.all()

for instance in instance_list:
    inst = Ec2Instance(logger=logger, instance_id=instance.id,
                        account_id=accnt.account_id, session=accnt.session ,
                        region=accnt.region)
    all_dfs.append(inst.heal_instance(inst.instance_id))
are_dfs = True
for df in all_dfs:
    if not isinstance(df, pd.DataFrame):
        are_dfs = False
        break
if are_dfs:
    combined_df = pd.concat(all_dfs, ignore_index=True)
    combined_df.to_csv(output_file, index=False)
else:
    logger.info("!!! No Instances in Repaired !!!")
    

# inst = Ec2Instance(logger=logger, instance_id=instance_scope,
#                     account_id=account_id, session=session,region='us-west-2')
# inst.heal_instance(instance_scope)

