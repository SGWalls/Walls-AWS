import boto3
import os
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError


userprofile = os.environ["USERPROFILE"]

def assume_role(account_id, role_name="AWSControlTowerExecution"):
    """Assume role in target account"""
    sts_client = session.client('sts')
    try:
        if not isinstance(account_id, str) or not account_id.isdigit():
            raise ValueError("Invalid account_id: must be a string of digits")
        if not isinstance(role_name, str) or not role_name.isalnum():
            raise ValueError("Invalid role_name: must be an alphanumeric string")
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='LoadBalancerAudit'
        )
        return response['Credentials']
    except ClientError as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return None

def get_account_list():
    """Get list of all accounts in the organization"""
    session = boto3.Session(profile_name='ct_master')
    org_client = session.client('organizations')
    accounts = []
    
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name']
                    })
    except ClientError as e:
        print(f"Error getting account list: {e}")
        
    return accounts

def get_lb_data(account):
    """Get Load Balancer and target data for an account"""
    lb_data = []
    if account['id'] != '662627786878':
        credentials = assume_role(account['id'])
        
        if not credentials:
            return lb_data

        # Create session with assumed role credentials
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-west-2'
        )
    else:
        session = boto3.Session(profile_name='ct_master',region_name='us-west-2')

    elb_client = session.client('elbv2')
    ec2_client = session.client('ec2')

    try:
        # Get all load balancers
        paginator = elb_client.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                lb_info = {
                    'AccountID': account['id'],
                    'AccountName': account['name'],
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'Type': lb['Type'],
                    'Scheme': lb.get('Scheme', ''),
                    'DNSName': lb.get('DNSName', ''),
                    'VpcId': lb['VpcId'],
                    'State': lb['State']['Code']
                }

                # Get target groups for this LB
                tg_paginator = elb_client.get_paginator('describe_target_groups')
                for tg_page in tg_paginator.paginate(LoadBalancerArn=lb['LoadBalancerArn']):
                    for tg in tg_page['TargetGroups']:
                        # Get targets in this target group
                        try:
                            targets = elb_client.describe_target_health(
                                TargetGroupArn=tg['TargetGroupArn']
                            )['TargetHealthDescriptions']

                            for target in targets:
                                target_info = lb_info.copy()
                                target_info.update({
                                    'TargetGroupName': tg['TargetGroupName'],
                                    'TargetId': target['Target']['Id'],
                                    'TargetHealth': target['TargetHealth']['State'],
                                    'Protocol': tg.get('Protocol',''),
                                    'Port': tg.get('Port','')
                                })

                                # Get EC2 instance details if target is an instance
                                if target['Target']['Id'].startswith('i-'):
                                    try:
                                        instance = ec2_client.describe_instances(
                                            InstanceIds=[target['Target']['Id']]
                                        )['Reservations'][0]['Instances'][0]
                                        
                                        # Get instance name from tags
                                        instance_name = ''
                                        for tag in instance.get('Tags', []):
                                            if tag['Key'] == 'Name':
                                                instance_name = tag['Value']
                                                break

                                        target_info.update({
                                            'InstanceName': instance_name,
                                            'InstanceType': instance['InstanceType'],
                                            'PrivateIP': instance.get('PrivateIpAddress', ''),
                                            'PublicIP': instance.get('PublicIpAddress', '')
                                        })
                                    except ClientError:
                                        pass
                                lb_data.append(target_info)
                        except ClientError as e:
                            print(f"Error getting target data for LB {lb['LoadBalancerName']}: {e}")
    except ClientError as e:
        print(f"Error getting LB data for account {account['id']}: {e}")

    return lb_data

def main():
    # Get list of accounts
    
    accounts = get_account_list()
    all_lb_data = []

    # Use ThreadPoolExecutor to process accounts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(get_lb_data, accounts))
        
    # Flatten results
    for result in results:
        all_lb_data.extend(result)

    # Convert to DataFrame and export to Excel
    if all_lb_data:
        df = pd.DataFrame(all_lb_data)
        current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        excelfilename = (f"LoadBalancer_Instance_Mapping-{current_time}.xlsx")
        export_path = (
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
            "LoadBalancer_Instance_Map\\"
        )
        if not os.path.exists(export_path):
            os.makedirs(export_path)

        output_file = excelfilename
        
        # Define column order
        columns = [
            'AccountID', 'AccountName', 'LoadBalancerName', 'Type', 'Scheme', 'DNSName',
            'VpcId', 'State', 'TargetGroupName', 'TargetId',
            'TargetHealth', 'Protocol', 'Port', 'InstanceName', 'InstanceType', 'PrivateIP', 'PublicIP'
        ]
        
        # Reorder columns and write to Excel
        excelfilepath = os.path.join(export_path, excelfilename)    
        df = df.reindex(columns=columns)
        df.to_excel(excelfilepath, index=False)
        print(f"Data exported to {output_file}")
    else:
        print("No data found")

if __name__ == "__main__":
    session = boto3.Session(profile_name='ct_master')
    main()
