import boto3
import botocore
from botocore.exceptions import ClientError

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='ShieldAdvancedConfig'
        )
        return assumed_role['Credentials']
    except ClientError as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return None

def get_cloudfront_distributions(shield_client):
    try:
        # Get all protected resources first
        protected_resources = shield_client.list_protections()
        protected_arns = [p['ResourceArn'] for p in protected_resources.get('Protections', [])]
        
        # Get CloudFront distributions using the credentials
        cf_client = boto3.client('cloudfront')
        paginator = cf_client.get_paginator('list_distributions')
        distributions = []
        
        for page in paginator.paginate():
            if 'Items' in page['DistributionList']:
                for dist in page['DistributionList']['Items']:
                    dist_arn = f"arn:aws:cloudfront::{dist['Id']}"
                    if dist_arn not in protected_arns:
                        distributions.append({
                            'Id': dist['Id'],
                            'Arn': dist_arn
                        })
        
        return distributions
    except ClientError as e:
        print(f"Error getting CloudFront distributions: {e}")
        return []

def enable_shield_protection(shield_client, distribution):
    try:
        shield_client.create_protection(
            Name=f"CloudFront-Distribution-{distribution['Id']}",
            ResourceArn=distribution['Arn']
        )
        print(f"Successfully enabled Shield Advanced protection for distribution {distribution['Id']}")
    except ClientError as e:
        print(f"Error enabling Shield Advanced protection for distribution {distribution['Id']}: {e}")

def get_application_load_balancer_arns(elbv2_client):
    try:
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        arns = []

        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                arns.append(lb['LoadBalancerArn'])

        return arns
    except ClientError as e:
        print(f"Error getting Application Load Balancer ARNs: {e}")
        return []

def get_lambda_function_arns(lambda_client):
    try:
        paginator = lambda_client.get_paginator('list_functions')
        arns = []

        for page in paginator.paginate():
            for function in page['Functions']:
                arns.append(function['FunctionArn'])

        return arns
    except ClientError as e:
        print(f"Error getting Lambda function ARNs: {e}")
        return []

def main():
    # Initialize the Organizations client
    org_client = boto3.client('organizations')
    
    try:
        # List all accounts in the organization
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                account_id = account['Id']
                print(f"\nProcessing account: {account_id}")
                
                # Assume role in the target account
                credentials = assume_role(account_id, 'AWSControlTowerExecution')
                if not credentials:
                    continue
                
                # Create Shield client with assumed role credentials
                shield_client = boto3.client(
                    'shield',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name='us-east-1'  # Shield Advanced is only available in us-east-1
                )
                
                # Get unprotected CloudFront distributions
                distributions = get_cloudfront_distributions(shield_client)
                
                if not distributions:
                    print(f"No unprotected CloudFront distributions found in account {account_id}")
                    continue
                
                # Enable Shield Advanced protection for each distribution
                for distribution in distributions:
                    enable_shield_protection(shield_client, distribution)
                
    except ClientError as e:
        print(f"Error accessing Organizations: {e}")

if __name__ == "__main__":
    main()
