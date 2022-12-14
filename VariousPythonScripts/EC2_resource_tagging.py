import boto3
import json
import os
import logging
import pprint
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from configparser import ConfigParser


# Setting up the logger #
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Sets the User Profile and .aws directory location
userprofile = os.environ["USERPROFILE"]
aws = "/.aws/"
aws_config_file = f"{userprofile}{aws}config"
region = "us-west-2"

# The function block are responsible for the tasks that check if CLIv2 exists 
# and then check if there is an existing named profile for the account that is 
# targetted, then to create the profile if not.
def awscliv2_exists():
    "Return True if AWSCLIv2 is installed"
    return os.path.exists(
        os.path.dirname("C:/Program Files/Amazon/AWSCLIV2")
    )


def append_profiles(filepath, account_id, account_name, role_name, 
                    filetype="config"):
    delimiter()
    print("Adding profile to your aws config file")
    config = ConfigParser()
    config.read(filepath)
    if filetype.lower() == "config":
        profile = "profile "
    if filetype.lower() == "credentials":
        profile = ""
    config[f"{profile}{account_name}"] = dict(
        sso_start_url = "https://globeaws.awsapps.com/start",
        sso_region = region,
        sso_account_id = account_id,
        sso_role_name = role_name,
        region = region,
        ca_bundle = "C:\\Program Files\\Amazon\\AWSCLIV2\\nskp_config\\netskope-cert-bundle.pem",
        output = "json",
    )    
    with open(filepath, "w") as configfile:
        config.write(configfile)
    delimiter()
    print(f"Added profile {profile}{account_name} to your aws config file")


def test_token(session):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 


def check_input(inpt: str):
    if inpt:
        return True
    else:
        print("Input is empty!")
        return False


def check_format(accountId):
    if (len(accountId) == 12 and accountId.isdigit()):
        return True
    else:
        print("Account ID is INVALID!")
        return False


def delimiter(symbol='='):
    logger.info(symbol * 120)


def generate_arn(instanceId):
    return f"arn:aws:ec2:us-west-2:{account_id}:instance/{instanceId}"


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

# Asks for the Account ID input, and will loop if the response is not valid
while True: 
    account_id = input("Enter the AWS Account ID of the target Account: ")
    if not check_input(account_id):
        continue
    elif not check_format(account_id):
        continue
    else:
        break
# Asks for the name of the account. Will be used as the profile name in the 
# config file    
target_account_name = input("Enter the name of the Target Account: ")
# Reformat the input to lower-cased and replace any spaces with underscores
target_account_name = target_account_name.replace(" ","_").lower()
# Asks for the IAM role that is used to access the account
role_name = input(
    "Name of the role you use for accessing the account (Case Sensitive):  "
)
# Checking if the CLIv2 exists, then adds the profile to the config file
if awscliv2_exists:
    append_profiles(aws_config_file,account_id,target_account_name,role_name)
# Configuring a session using the named profile
session = boto3.session.Session(
    profile_name=target_account_name,
    region_name=region
)
# Configure STS then check the token to reprompt for AWS SSO login if needed
sts = session.client('sts')
test_token(session)

# Sets the clients for ec2 and resourcegroupstaggingapi
ec2 = session.client('ec2')
tagging = session.client('resourcegroupstaggingapi')
# Setting an empty list to later populate with the ARNs of EC2 Instances
arn_list = []
# Queries and returns a list of instances
reservation_list = ec2.describe_instances()['Reservations']
# Iterates this list to extract the instnaceIDs
for reservation in reservation_list:
    for instance in reservation['Instances']:
        # appends the instanceID to the arn_list in an ARN format
        arn_list.append(generate_arn(instance['InstanceId']))
        ###
        ###
        # tagging.tag_resources(
        #     ResourceARNList = [generate_arn(instance['InstanceId'])],
        #     Tags={
        #         'map-migrated': 'd-server-01vd8mgitxzw0p'        
        #     }
        # )
# Calls the resourcegroupstaggingapi to apply the defined tag to the resources
# in the arn_list.
# Split the ARN list in to lists of 20 items.
arn_chunks = list(chunks(arn_list,20))
for i in arn_chunks:
    tagging.tag_resources(
        ResourceARNList = i,
        Tags={
            'testing': 'sgwallsTest'        
        }
    )
    # tagging.untag_resources(
    #     ResourceARNList=i,
    #     TagKeys=[
    #         "test",
    #         "testing"
    #     ]
    # )

