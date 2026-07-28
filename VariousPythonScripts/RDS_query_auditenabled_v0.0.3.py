import boto3
import csv
from typing import Dict, Any
from datetime import datetime

def get_session(profile_name):
    session = boto3.Session(profile_name=profile_name,region_name='us-west-2')
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
                parameters = rds_client.describe_db_parameters(
                    DBParameterGroupName=parameter_group
                )['Parameters']
                
                pgaudit_params = {
                    param['ParameterName']: param['ParameterValue']
                    for param in parameters
                    if 'pgaudit' in param['ParameterName'].lower()
                    and 'ParameterValue' in param
                }
                
                audit_enabled = bool(pgaudit_params)
                cloudwatch_enabled = 'postgresql' in log_exports
                
            elif 'mysql' in engine or 'aurora-mysql' in engine:
                # Check MySQL audit logging
                parameter_group = instance['DBParameterGroups'][0]['DBParameterGroupName']
                parameters = rds_client.describe_db_parameters(
                    DBParameterGroupName=parameter_group
                )['Parameters']
                
                audit_params = {
                    param['ParameterName']: param['ParameterValue']
                    for param in parameters
                    if 'audit' in param['ParameterName'].lower()
                    and 'ParameterValue' in param
                }
                
                audit_enabled = any(
                    param for param in audit_params.values()
                    if str(param).upper() in ('ON', 'FORCE_PLUS_PERMANENT')
                )
                cloudwatch_enabled = 'audit' in log_exports
            
            results.append({
                'AccountID': account_id,
                'ClusterName': cluster_name,
                'DBInstanceName': instance_id,
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
    
    # Prepare CSV output
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports'
    csv_filename = f'rds_audit_logging_status_{timestamp}.csv'
    csv_filename = f'{file_path}\\{csv_filename}'
    
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['AccountID', 'ClusterName', 'DBInstanceName', 
                     'AuditLogsEnabled', 'CloudWatchEnabled']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for account in accounts:
            if account['Status'] != 'ACTIVE':
                continue
                
            print(f"Checking account: {account['Id']}")
            
            try:
                # Assume role in member account
                sts_client = session.client('sts')
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
