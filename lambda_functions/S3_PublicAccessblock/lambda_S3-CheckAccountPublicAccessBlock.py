import boto3
import os
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']


class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()

    def get_credentials(self):
        return self.assume_role('ent_setS3AccountPubBlock')

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

    def s3_account_pab(self):
        s3control = self.client_config('s3control')
        try:
            publicAccessSetting =  s3control.get_public_access_block(
                AccountId=self.account_id
            )['PublicAccessBlockConfiguration']
        except s3control.exceptions.NoSuchPublicAccessBlockConfiguration as e:
            logger.info("Account does not have any Public Access Block configurations")
            publicAccessSetting = {
                    'PublicAccessBlock': False                
            }
        if not all(publicAccessSetting.values()):
            logger.info("Putting Public Access Block. . .")
            s3control.put_public_access_block(
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                },
                AccountId=self.account_id
            )
        else:
            logger.info("Public Access Block Already Enabled.")
        return


def delimiter(symbol='='):
    logger.info(symbol * 120)

def lambda_handler(event, context):
    logger.info(event)
    try:
        account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]
    except KeyError:
        print(f"Unable to get an account Id from this event: {event}")
        return

    target_account = Account(account_id=account_id,region=region)
    target_account.s3_account_pab()
