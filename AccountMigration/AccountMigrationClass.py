import boto3
import json
import os
import logging
import inspect
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

ROOT_ID = "r-7w8p"
ASSUMED_ROLE = "OrganizationAccountAccessRole" 
NEW_RESOLVER_RULE = "rslvr-rr-b333b2fa07e04cddb"

class Account():
    def __init__(
            self, account_id, logger, master_obj=None, org_root=ROOT_ID, role_name=ASSUMED_ROLE,
            region="us-west-2"):
        self.logger = logger
        self.accountid = account_id        
        if master_obj:
            self.master = master_obj
            self.email = self.master.org.describe_account(AccountId=self.accountid)['Account']['Email']
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
        self.guardduty = self.session.client("guardduty")
        self.securityhub = self.session.client("securityhub")
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
            self.logger.info(f"Removing Config Recorder in region: {region}")
            client = self.client_config(self.credentials,"config",region)
            recorder = client.describe_configuration_recorders()
            if recorder['ConfigurationRecorders']:
                recorder = recorder['ConfigurationRecorders'][0]
                channel = client.describe_delivery_channels()['DeliveryChannels'][0]
                self.logger.info(recorder)
                self.logger.info(channel)
                self.logger.info("...Stopping Config Recorder...")
                client.stop_configuration_recorder(
                    ConfigurationRecorderName = recorder['name']
                )
                self.logger.info("...Deleting Config Delivery Channel...")
                client.delete_delivery_channel(
                    DeliveryChannelName=channel['name']
                )
                self.logger.info("...Deleting Config Recorder...")
                client.delete_configuration_recorder(
                    ConfigurationRecorderName = recorder['name']
                )
                self.logger.info(f"{self.accountid}: Removed Configuration Recorder and "
                      f"Delivery Channel in region {region}")
            else:
                self.logger.info(
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
            self.logger.info(f"Account with ID: {self.accountid} is leaving the Organization")
            client.leave_organization()
        except Exception as e:
            raise

    def accept_invitation(self,identifier):
        self.logger.info(f"Accepting the handshake with ID: {identifier}")
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


class Master():
    def __init__(self, accountId, logger):
        self.logger = logger
        self.accountId = accountId         
        if accountId == "741252614647":
            self.session = boto3.session.Session(
                                profile_name="master",
                                region_name="us-west-2"
                            )
            self.rootId = "r-7w8p"
            self.executionRole = "OrganizationAccountAccessRole"
            self.org = self.session.client("organizations")
            self.sts = self.session.client("sts")
            self.guardduty = self.session.client("guardduty")
            self.detectorId = self.guardduty.list_detectors()['DetectorIds'][0]
            self.securityhub = self.session.client("securityhub")
        elif accountId == "662627786878":
            self.session = boto3.session.Session(
                                profile_name="ct_master",
                                region_name="us-west-2"
                            )
            self.get_caller_account()
            self.rootId = "r-mdy1"
            self.executionRole = "AWSControlTowerExecution"
            self.org = self.session.client("organizations")
            self.sts = self.session.client("sts")
            self.auditAccount = Account(
                                    '124178480447',
                                    logger=self.logger,
                                    master_obj=self,
                                    org_root=self.rootId,
                                    role_name=self.executionRole
                                )
            self.guardduty = self.auditAccount.guardduty
            self.detectorId = self.guardduty.list_detectors()['DetectorIds'][0]
            self.securityhub = self.auditAccount.securityhub
        else:
            print("Account ID is not a valid Master Account")
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
        response = self.org.invite_account_to_organization(
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

    def guardduty_remove(self,account_id):
        self.guardduty.disassociate_members(
                DetectorId=self.detectorId,
                AccountIds=[account_id]
                )
        return

    def guardduty_add(self,account_id,account_email):
        try:
            self.guardduty.create_members(
                    DetectorId=self.detectorId,
                    AccountDetails=[
                        {
                            'AccountId':account_id,
                            'Email':account_email
                        }
                    ]
                )
        except Exception as e:
            message = {'FILE': __file__.split('/')[-1], 'CLASS': self.__class__.__name__,
                       'METHOD': inspect.stack()[0][3], 'EXCEPTION': str(e)}
            self.logger.info(delimiter("!"))
            self.logger.exception(message)
            self.logger.info(delimiter("!"))
        return

    def securityhub_remove(self,account_id):
        self.securityhub.disassociate_members(
            AccountIds=[account_id]
            )
        return

    def securityhub_add(self,account_id,account_email):
        try:
            self.securityhub.create_members(
            AccountDetails=[
                {
                    'AccountId':account_id,
                    'Email':account_email
                }
            ]
        )
        except Exception as e:
            message = {'FILE': __file__.split('/')[-1], 'CLASS': self.__class__.__name__,
                       'METHOD': inspect.stack()[0][3], 'EXCEPTION': str(e)}
            self.logger.info(delimiter("!"))
            self.logger.exception(message)
            self.logger.info(delimiter("!"))
        return

    def deregister_security(self,account_id):
        self.guardduty_remove(account_id)
        self.securityhub_remove(account_id)

    def register_security(self,account_id,account_email):
        self.guardduty_add(account_id,account_email)
        self.securityhub_add(account_id,account_email)


def delimiter(symbol='='):
    logger.info(symbol * 120)


def create_filter(name=None, values=[]):
    return {
            "Name": name,
            "Values": values
        }


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


if __name__ == "__main__":
    userprofile = os.environ["USERPROFILE"]
    log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\AccountMoveProcess\\"
    )
    log_file_name = f"account-org-move-{datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
    if not os.path.exists(log_path):
        os.makedirs(log_path)

    logger = create_logger("AccountMoveLogger",log_path,log_file_name)
    region_list = ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 
                   'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 
                   'eu-central-1', 'eu-north-1', 'eu-west-1', 'eu-west-2', 
                   'eu-west-3', 'sa-east-1', 'us-east-1', 
                   'us-east-2', 'us-west-1', 'us-west-2']


    legacy_master = Master('741252614647', logger)
    new_master = Master('662627786878', logger)

    target_input = input("List the Account IDs for the target account " 
                        "(Separate multiple entries with a comma ','): ")

    accounts = target_input.split(',')                    

    for account in accounts:
        delimiter()
        logger.info(f"Beginning Account Re-Association Process.  Current Account: {account}")
        accnt = Account(
            account_id=account,
            logger=logger,
            master_obj=legacy_master
        )
        logger.info(f"Account original OU: {accnt.ou}")
        for vpc in accnt.vpcs:
            print(vpc.id) 
        logger.info(f"Inviting Account {account} to new Organization...")
        handshake_info = new_master.invite_account(account)
        logger.info(f"Beginning AWS Config Cleanup. Removing Legacy settings...")
        accnt.config_cleanup()
        logger.info("Beginning Security Service deregistration from Legacy Environment...")
        legacy_master.deregister_security(accnt.accountid)
        accnt.leave_organization()
        logger.info("Accepting invitation to new Organization...")
        accnt.accept_invitation(handshake_info['Id'])
        logger.info("Beginning registration of Security Services in the New Organiziaton...")
        new_master.register_security(accnt.accountid,accnt.email)
        logger.info(f"Moving Account {account} to the correct OU...")
        new_master.move_account(
            accountId=accnt.accountid,
            sourceId=new_master.rootId,
            destinationId=new_master.find_ou(
                identifier=accnt.ou['Name']
                )
            )
        logger.info("Beginning update of ResolverRules for Account VPCs...")
        accnt.update_resolver_rule(accnt.vpcs)
        
