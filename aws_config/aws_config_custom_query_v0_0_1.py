import boto3
import os
import sys
import json
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)
from helpers.helper import validate_sso_token, get_org_account_list
from helpers.Account import Account
from botocore.exceptions import ClientError
from botocore.exceptions import WaiterError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

session = boto3.Session(profile_name='audit')
config = session.client('config')

def generate_identifier_params(SourceAccountId,SourceRegion,ResourceId,
                               ResourceType,ResourceName):
    return {
        'SourceAccountId': SourceAccountId,
        'SourceRegion': SourceRegion,
        'ResourceId': ResourceId,
        'ResourceType': ResourceType,
        'ResourceName': ResourceName
    }

sg_list = config.batch_get_aggregate_resource_config(
    ConfigurationAggregatorName='AWS_Security_Groups',
    ResourceIdentifiers=[
        generate_identifier_params('123456789012','us-east-1','sg-12345678','AWS::EC2::SecurityGroup','test-sg'),
        generate_identifier_params('123456789012','us-east-1','sg-12345678','AWS::EC2::SecurityGroup','test-sg')
    ])


import boto3
from botocore.exceptions import ClientError
import json

class ConfigResourceFinder:
    def __init__(self, aggregator_name):
        self.config_client = boto3.client('config')
        self.aggregator_name = aggregator_name

    def execute_query(self, query):
        """
        Execute AWS Config query with pagination
        """
        try:
            paginator = self.config_client.get_paginator('select_aggregate_resource_config')
            all_results = []
            
            for page in paginator.paginate(
                ConfigurationAggregator=self.aggregator_name,
                Expression=query
            ):
                for result in page['Results']:
                    all_results.append(json.loads(result))
            return all_results
        except ClientError as e:
            print(f"AWS Error: {e.response['Error']}")
            raise

    def get_tagged_security_groups(self):
        """
        Get security groups with specific FMS policy tag
        """
        query = """
            SELECT
                resourceId,
                accountId,
                awsRegion,
                configuration.groupName,
                configuration.tags
            WHERE
                resourceType = 'AWS::EC2::SecurityGroup'
                AND configuration.tags[?Key=='fms-policy' && Value=='Role_web']
        """
        return self.execute_query(query)

    def get_resources_using_security_groups(self, security_group_ids):
        """
        Get resources that use the specified security groups
        """
        if not security_group_ids:
            return []

        # Create a query to find resources using these security groups
        sg_query = """
            SELECT
                resourceId,
                resourceType,
                accountId,
                awsRegion,
                configuration
            WHERE
                resourceType IN ('AWS::EC2::Instance', 'AWS::ElasticLoadBalancingV2::LoadBalancer')
                AND relationships.resourceId IN {
                    SELECT resourceId
                    WHERE resourceType = 'AWS::EC2::SecurityGroup'
                    AND configuration.tags[?Key=='fms-policy' && Value=='Role_web']
                }
        """
        return self.execute_query(sg_query)

def main():
    try:
        # Initialize the finder with your aggregator name
        finder = ConfigResourceFinder('your-aggregator-name')

        # First, get all security groups with the FMS policy tag
        print("Finding tagged security groups...")
        tagged_sgs = finder.get_tagged_security_groups()
        
        if not tagged_sgs:
            print("No security groups found with the specified tag")
            return

        # Extract security group IDs
        sg_ids = [sg['resourceId'] for sg in tagged_sgs]
        
        print(f"\nFound {len(tagged_sgs)} tagged security groups:")
        for sg in tagged_sgs:
            print(f"\nSecurity Group: {sg['resourceId']}")
            print(f"Account: {sg['accountId']}")
            print(f"Region: {sg['awsRegion']}")
            print(f"Name: {sg['configuration']['groupName']}")

        # Get resources using these security groups
        print("\nFinding resources using these security groups...")
        resources = finder.get_resources_using_security_groups(sg_ids)

        if not resources:
            print("No resources found using the tagged security groups")
            return

        # Group resources by type
        ec2_instances = []
        load_balancers = []

        for resource in resources:
            if resource['resourceType'] == 'AWS::EC2::Instance':
                ec2_instances.append(resource)
            elif resource['resourceType'] == 'AWS::ElasticLoadBalancingV2::LoadBalancer':
                load_balancers.append(resource)

        # Print EC2 instances
        print(f"\nFound {len(ec2_instances)} EC2 instances:")
        for instance in ec2_instances:
            print(f"\nInstance ID: {instance['resourceId']}")
            print(f"Account: {instance['accountId']}")
            print(f"Region: {instance['awsRegion']}")
            if 'configuration' in instance:
                print(f"Instance Type: {instance['configuration'].get('instanceType', 'N/A')}")

        # Print Load Balancers
        print(f"\nFound {len(load_balancers)} Load Balancers:")
        for lb in load_balancers:
            print(f"\nLoad Balancer: {lb['resourceId']}")
            print(f"Account: {lb['accountId']}")
            print(f"Region: {lb['awsRegion']}")
            if 'configuration' in lb:
                print(f"Type: {lb['configuration'].get('type', 'N/A')}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

