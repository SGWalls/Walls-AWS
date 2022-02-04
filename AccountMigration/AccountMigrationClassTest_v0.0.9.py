import boto3
import json
import os
import logging
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ROOT_ID = "r-7w8p"
ASSUMED_ROLE = "OrganizationAccountAccessRole" 
NEW_RESOLVER_RULE = "rslvr-rr-b333b2fa07e04cddb"
# session = boto3.session.Session(
#     profile_name="master",
#     region_name="us-west-2"
# )
# dest_session = boto3.session.Session(
#     profile_name="ct_master",
#     region_name="us-west-2"
# )
# dest_org = dest_session.client('organizations')
# sts = session.client("sts")
# org = session.client("organizations")
region_list = ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 
               'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 
               'eu-central-1', 'eu-north-1', 'eu-west-1', 'eu-west-2', 
               'eu-west-3', 'sa-east-1', 'us-east-1', 
               'us-east-2', 'us-west-1', 'us-west-2']

class Account:
    def __init__(
            self,account_id, master_obj, org_root=ROOT_ID, role_name=ASSUMED_ROLE,
            region="us-west-2"):            
        self.accountid = account_id
        self.master = master_obj
        self.root_id = org_root
        self.rolename = role_name
        self.credentials = self.assume_role(self.accountid,
                                            "AccountMigrationTasks")
        self.session = boto3.session.Session(
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name=region
        )
        self.org = self.session.client("organizations")
        self.ec2 = self.session.resource("ec2")
        self.vpcs = self.get_vpcs()
        self.ou = self.get_ou()

    def assume_role(self,account_id,session_name,duration=900):
        response = self.master.session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.rolename}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']
    
    def client_config(self,creds,service,region="us-west-2"):
        response = boto3.session.Session().client(
            aws_access_key_id = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token = creds['SessionToken'],
            region_name = region,
            service_name = service
        )
        return response
    
    def get_ou(self):        
        org = self.master.session.client("organizations")
        ou = [ou['Id'] for ou in org.list_children(ParentId=self.root_id,
                            ChildType='ORGANIZATIONAL_UNIT')['Children']
            if self.accountid in [
                account for account in [
                    acctid['Id'] for acctid in org.list_children(
                        ParentId=ou['Id'],
                        ChildType='ACCOUNT')['Children']
                    ]
                ]
            ]
        ou_details = org.describe_organizational_unit(
            OrganizationalUnitId=ou[0])['OrganizationalUnit']
        return ou_details
    
    def config_cleanup(self):
        for region in region_list:
            print(region)
            client = self.client_config(self.credentials,"config",region)
            recorder = client.describe_configuration_recorders()
            if recorder['ConfigurationRecorders']:
                recorder = recorder['ConfigurationRecorders'][0]
                channel = client.describe_delivery_channels()['DeliveryChannels'][0]
                print(recorder)
                print(channel)
                # client.stop_configuration_recorder(
                #     ConfigurationRecorderName = recorder['name']
                # )
                # client.delete_delivery_channel(
                #     DeliveryChannelName=channel['name']
                # )
                # client.delete_configuration_recorder(
                #     ConfigurationRecorderName = recorder['name']
                # )
                print(f"{self.accountid}: Removed Configuration Recorder and "
                      f"Delivery Channel in region {region}")
            else:
                print(
                    f"{self.accountid}: No Configuration Recorder in {region}"
                )
        return

    def get_vpcs(self):
        vpc_list = self.ec2.vpcs.filter(
            Filters = [
                create_filter('isDefault',['false'])
            ]
        )
        return vpc_list

    def leave_organization(self):
        client = self.org
        try:
            print(f"Account with ID: {self.accountid} is leaving the Organization")
            client.leave_organization()
        except Exception as e:
            raise

    def accept_invitation(self,identifier):
        print(f"Accepting the handshake with ID: {identifier}")
        self.org.accept_handshake(
            HandshakeId=identifier
        )

    def update_resolver_rule(self,vpc_list,resolverRuleId=NEW_RESOLVER_RULE):
        client = self.session.client("route53resolver")
        for vpc in list(vpc_list):
            client.associate_resolver_rule(
                ResolverRuleId=resolverRuleId,
                VPCId=vpc.id
            )
        return


class Master:
    def __init__(self,accountId):
        self.accountId = accountId         
        if accountId == "741252614647":
            self.session = boto3.session.Session(
                                profile_name="master",
                                region_name="us-west-2"
                            )
            self.rootId = "r-7w8p"
            self.executionRole = "OrganizationAccountAccessRole"
        elif accountId == "662627786878":
            self.session = boto3.session.Session(
                                profile_name="ct_master",
                                region_name="us-west-2"
                            )            
            self.rootId = "r-mdy1"
            self.executionRole = "AWSControlTowerExecution"
        else:
            print("Account ID is not a valid Master Account")
        self.org = self.session.client("organizations")
        self.sts = self.session.client("sts")
        self.get_caller_account()

    def get_caller_account(self):
        try:
            return self.session.client('sts').get_caller_identity().get('Account')
        except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
            if "expired or is otherwise invalid" in str(e):
                delimiter()
                logger.info(e)
                logger.info("Reinitiating SSO Login...")
                os.system(f"aws sso login --profile {self.session.profile_name}")
                return self.session.client('sts').get_caller_identity().get('Account')

    def invite_account(self,identifier):        
        response = self.org.invite_account_to_organizaiton(
            Target={
                'Id':identifier,
                'Type':'ACCOUNT'
            }
        )
        return response['Handshake']

    def move_account(self,accountId,sourceId,destinationId):
        self.org.move_account(
            AccountId=accountId,
            SourceParentId=sourceId,
            DestinationParentId=destinationId
        )
        return

    def find_ou(self,identifier):
        ou = [ ou for ou in self.org.list_children(ParentId=self.rootId,
                            ChildType='ORGANIZATIONAL_UNIT')['Children']
        if identifier == self.org.describe_organizational_unit(
            OrganizationalUnitId=ou['Id'])['OrganizationalUnit']['Name']
        ]        
        response = ou[0]['Id']
        return response


def delimiter(symbol='='):
    logger.info(symbol * 120)


def create_filter(name=None, values=[]):
    return {
            "Name": name,
            "Values": values
        }


legacy_master = Master('741252614647')
new_master = Master('662627786878')

target_input = input("List the Account IDs for the target account " 
                    "(Separate multiple entries with a comma ','): ")

accounts = target_input.split(',')                    

for account in accounts:
    accnt = Account(
        account_id=account,
        master_obj=legacy_master)
    print(accnt.ou)
    for vpc in accnt.vpcs:
        print(vpc.id)    
    # handshake_info = new_master.invite_account(account)
    # accnt = Account(account)
    # accnt.config_cleanup()
    # accnt.leave_organization()
    # accnt.accept_invitation(handshake_info['Id'])
    # accnt.update_resolver_rule(accnt.vpcs)
    # new_master.move_account(
    #     accountId=accnt.accountid,
    #     sourceId=new_master.rootId,
    #     destinationId=new_master.find_ou(
    #         identifier=accnt.ou['Name']
    #         )
    #     )
