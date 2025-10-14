import boto3
import csv
import subprocess, shlex
from typing import Dict, Any
from datetime import datetime

addtl_accounts = [
    {
        'Id':'741252614647',
        'Arn':'arn:aws:organizations::741252614647:account/o-tuwjxnhqr4/741252614647',
        'Email': 'TorchmarkAWS@torchmarkcorp.com',
        'Name': 'Torchmark AWS',
        'Status':'ACTIVE',
        'JoinedMethod': 'INVITED',
        'JoinedTimestamp': '2018-10-09T16:21:23.832000-05:00'
    }
]

def refresh_sso_token(profile_name):
    try:
        subprocess.run(shlex.split(
            f"aws sso login --profile {profile_name}"
        ))
        print(f"SSO token refreshed for profile {profile_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to refresh SSO token: {e}")
        exit(1)
        
def get_session(profile_name):
    session = boto3.Session(profile_name=profile_name)
    sts = session.client('sts')
    
    try:
        sts.get_caller_identity()
    except Exception:
        print(f"Session token invalid or expired. Refreshing...")
        refresh_sso_token(profile_name)
        session = boto3.Session(profile_name=profile_name)
    
    return session

def get_member_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def get_cluster_info(rds_client) -> Dict[str, str]:
    """Get mapping of DB instances to their cluster names"""
    cluster_mapping = {}
    try:
        clusters = rds_client.describe_db_clusters()['DBClusters']
        for cluster in clusters:
            for instance in cluster.get('DBClusterMembers', []):
                cluster_mapping[instance['DBInstanceIdentifier']] = cluster['DBClusterIdentifier']
    except rds_client.exceptions.DBClusterNotFoundFault:
        pass
    return cluster_mapping

def get_cluster_parameters(rds_client, cluster_identifier):
    """Get cluster parameter group settings for an Aurora cluster"""
    parameters = {}
    try:
        cluster = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_identifier)['DBClusters'][0]
        parameter_group = cluster['DBClusterParameterGroup']
        paginator = rds_client.get_paginator('describe_db_cluster_parameters')
        for page in paginator.paginate(DBClusterParameterGroupName=parameter_group):
            for param in page['Parameters']:
                if param['ParameterName'] == 'server_audit_logging':
                    return {
                        'server_audit_logging': param['ParameterValue']
                    }
            parameters.update({
                param['ParameterName']: param['ParameterValue']
                for param in page['Parameters']
                if 'ParameterValue' in param
            })
        
        # parameters = rds_client.describe_db_cluster_parameters(
        #     DBClusterParameterGroupName=parameter_group
        # )['Parameters']
        
        # return {
        #     param['ParameterName']: param['ParameterValue']
        #     for param in parameters
        #     if 'ParameterValue' in param
        # }
        return parameters
    except Exception as e:
        print(f"Error getting cluster parameters for {cluster_identifier}: {e}")
        return {}

def check_rds_audit_logging(session, account_id: str) -> list:
    """Check audit logging configuration for RDS instances"""
    rds_client = session.client('rds')
    results = []
    
    # Get cluster mapping
    cluster_mapping = get_cluster_info(rds_client)
    
    try:
        instances = rds_client.describe_db_instances()['DBInstances']
        
        for instance in instances:
            instance_id = instance['DBInstanceIdentifier']
            engine = instance['Engine']
            
            # Determine if instance is part of cluster
            cluster_name = cluster_mapping.get(instance_id, 'standalone')
            
            audit_enabled = False
            cloudwatch_enabled = False
            
            # Check CloudWatch log exports
            log_exports = instance.get('EnabledCloudwatchLogsExports', [])
            
            if 'postgres' in engine:
                # Check PostgreSQL audit logging
                parameter_group = instance['DBParameterGroups'][0]['DBParameterGroupName']
                response = rds_client.describe_db_parameters(
                    DBParameterGroupName=parameter_group
                )
                parameters = response['Parameters']
                while "Marker" in response:
                    response = rds_client.describe_db_parameters(
                        DBParameterGroupName=parameter_group,
                        Marker=response["Marker"]
                    )
                    parameters.extend(response['Parameters'])
                pgaudit_params = {
                    param['ParameterName']: param['ParameterValue']
                    for param in parameters
                    if 'pgaudit' in param['ParameterName'].lower()
                    and 'ParameterValue' in param
                }
                
                audit_enabled = bool(pgaudit_params)
                cloudwatch_enabled = 'postgresql' in log_exports
                
            elif 'aurora-mysql' in engine:
                # For Aurora MySQL, check cluster parameter group
                if cluster_name != 'standalone':
                    cluster_params = get_cluster_parameters(rds_client, cluster_name)
                    audit_enabled = cluster_params.get('server_audit_logging', '0') == '1'
                    cloudwatch_enabled = 'audit' in log_exports
                
            elif 'mysql' in engine:
                # For RDS MySQL, check option group settings
                try:
                    option_group_name = instance['OptionGroupMemberships'][0]['OptionGroupName']
                    options = rds_client.describe_option_groups(
                        OptionGroupName=option_group_name
                    )['OptionGroupsList'][0]['Options']
                    
                    # Check if MARIADB_AUDIT_PLUGIN option is enabled
                    audit_enabled = any(
                        option['OptionName'] == 'MARIADB_AUDIT_PLUGIN'
                        for option in options
                    )
                    cloudwatch_enabled = 'audit' in log_exports
                except Exception as e:
                    print(f"Error checking option group for instance {instance_id}: {e}")
            
            elif 'sqlserver' in engine:
                try:
                    option_group_name = instance['OptionGroupMemberships'][0]['OptionGroupName']
                    options = rds_client.describe_option_groups(
                        OptionGroupName=option_group_name
                    )['OptionGroupsList'][0]['Options']
                    
                    audit_enabled = any(
                        option['OptionName'] == 'SQLSERVER_AUDIT'
                        for option in options
                    )
                    cloudwatch_enabled = "N/A"
                except Exception as e:
                    print(f"Error checking option group for instance {instance_id}: {e}")
                    
            results.append({
                'AccountID': account_id,
                'ClusterName': cluster_name,
                'DBInstanceName': instance_id,
                'Engine': engine,
                'AuditLogsEnabled': str(audit_enabled),
                'CloudWatchEnabled': str(cloudwatch_enabled)
            })
            
    except Exception as e:
        print(f"Error checking account {account_id}: {e}")
    
    return results

def main():
    # Initialize session with your organization's management account
    session = get_session(profile_name='ct_master')  # Update profile name as needed
    org_client = session.client('organizations')
    
    # Get all accounts
    accounts = get_member_accounts(org_client)
    accounts.extend(addtl_accounts)
    # accounts = addtl_accounts
    # Prepare CSV output
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = r"C:\Users\sgwalls\Documents\AWS_Projects\Exports"
    csv_filename = f'rds_audit_logging_status_{timestamp}.csv'
    csv_filename = f'{file_path}\\{csv_filename}'  

    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['AccountID', 'ClusterName', 'DBInstanceName', 'Engine',  # Added Engine to fieldnames
                     'AuditLogsEnabled', 'CloudWatchEnabled']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Rest of the main function remains the same...
        for account in accounts:
            if account['Status'] != 'ACTIVE':
                continue
                
            print(f"Checking account: {account['Id']}")
            
            try:
                # Assume role in member account
                sts_client = session.client('sts')
                
                if account['Id'] == "741252614647":
                    assumed_session = boto3.Session(profile_name='master',region_name='us-west-2')
                elif account['Id'] == "662627786878":
                    assumed_session = boto3.Session(profile_name='ct_master',region_name='us-west-2')
                else:
                    assumed_role = sts_client.assume_role(
                        RoleArn=f"arn:aws:iam::{account['Id']}:role/AWSControlTowerExecution",
                        RoleSessionName="RDSAuditCheck"
                    ) 
                    assumed_session = boto3.Session(
                        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                        aws_session_token=assumed_role['Credentials']['SessionToken'],
                        region_name='us-west-2'  # Update as needed
                    )
                
                # Check RDS instances in the account
                results = check_rds_audit_logging(assumed_session, account['Id'])
                
                # Write results to CSV
                for result in results:
                    writer.writerow(result)
                    
            except Exception as e:
                print(f"Error processing account {account['Id']}: {e}")
                continue

if __name__ == "__main__":
    main()
