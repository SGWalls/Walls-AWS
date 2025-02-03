import boto3
from typing import Dict, Any
import subprocess, shlex
import concurrent.futures
from botocore.exceptions import ClientError

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
    session = boto3.Session(profile_name=profile_name,region_name='us-west-2')
    sts = session.client('sts')
    
    try:
        sts.get_caller_identity()
        return session
    except Exception:
        print(f"Session token invalid or expired. Refreshing...")
        refresh_sso_token(profile_name)
        return session 

def check_rds_audit_logging(session, db_instance_identifier: str = None) -> Dict[str, Any]:
    """
    Check audit logging configuration for RDS instances using AWS APIs only
    
    Args:
        db_instance_identifier: Optional specific RDS instance to check. If None, checks all instances.
    
    Returns:
        Dictionary containing audit logging status for RDS instances
    """
    rds_client = session.client('rds',region_name='us-west-2') if session else boto3.client('rds',region_name='us-west-2')
    results = {}
    
    # try:
        # Get instance details - either specific instance or all instances
    if db_instance_identifier:
        instances = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_instance_identifier
        )['DBInstances']
    else:
        instances = rds_client.describe_db_instances()['DBInstances']
    
    for instance in instances:
        instance_id = instance['DBInstanceIdentifier']
        engine = instance['Engine']
        
        result = {
            "engine": engine,
            "audit_enabled": False,
            "audit_config": {}
        }
        
        # Check PostgreSQL/Aurora PostgreSQL audit logging
        if 'postgres' in engine:
            result.update(_check_postgres_audit_config(rds_client,instance))
            
        # Check MySQL/Aurora MySQL audit logging
        elif 'mysql' in engine or 'aurora-mysql' in engine:
            result.update(_check_mysql_audit_config(rds_client,instance))
            
        # Check SQL Server audit logging
        elif 'sqlserver' in engine:
            result.update(_check_sqlserver_audit_config(rds_client,instance))
        
        results[instance_id] = result
        
    return results
        
    # except Exception as e:
    #     return {"error": str(e)}

def _check_postgres_audit_config(rds_client,instance: Dict) -> Dict[str, Any]:
    """Check PostgreSQL audit logging configuration from RDS parameters"""
    audit_config = {}
    
    try:
                
        # Get the parameter group details
        parameter_group = instance['DBParameterGroups'][0]['DBParameterGroupName']
        parameters = rds_client.describe_db_parameters(
            DBParameterGroupName=parameter_group
        )['Parameters']
        
        # Check for pgaudit-related parameters
        pgaudit_params = {
            param['ParameterName']: param['ParameterValue']
            for param in parameters
            if 'pgaudit' in param['ParameterName'].lower()
            and 'ParameterValue' in param
        }
        
        # Check CloudWatch log exports
        log_exports = instance.get('EnabledCloudwatchLogsExports', [])
        
        audit_enabled = bool(pgaudit_params) or 'postgresql' in log_exports
        
        return {
            "audit_enabled": audit_enabled,
            "audit_config": {
                "pgaudit_parameters": pgaudit_params,
                "cloudwatch_log_exports": log_exports
            }
        }
        
    except Exception as e:
        return {
            "audit_enabled": False,
            "error": str(e)
        }

def _check_mysql_audit_config(rds_client,instance: Dict) -> Dict[str, Any]:
    """Check MySQL audit logging configuration from RDS parameters"""
    audit_config = {}
    
    try:
        
        # Get the parameter group details
        parameter_group = instance['DBParameterGroups'][0]['DBParameterGroupName']
        parameters = rds_client.describe_db_parameters(
            DBParameterGroupName=parameter_group
        )['Parameters']
        
        # Check for audit-related parameters
        audit_params = {
            param['ParameterName']: param['ParameterValue']
            for param in parameters
            if 'audit' in param['ParameterName'].lower()
            and 'ParameterValue' in param
        }
        
        # Check CloudWatch log exports
        log_exports = instance.get('EnabledCloudwatchLogsExports', [])
        
        # MySQL audit log is enabled if audit_log parameter is set to ON or FORCE_PLUS_PERMANENT
        audit_enabled = any(
            param for param in audit_params.values()
            if str(param).upper() in ('ON', 'FORCE_PLUS_PERMANENT')
        ) or 'audit' in log_exports
        
        return {
            "audit_enabled": audit_enabled,
            "audit_config": {
                "audit_parameters": audit_params,
                "cloudwatch_log_exports": log_exports
            }
        }
        
    except Exception as e:
        return {
            "audit_enabled": False,
            "error": str(e)
        }

def _check_sqlserver_audit_config(rds_client,instance: Dict) -> Dict[str, Any]:
    """Check SQL Server audit logging configuration from RDS parameters"""
    try:
        # Check CloudWatch log exports
        log_exports = instance.get('EnabledCloudwatchLogsExports', [])
        
        # SQL Server audit is typically indicated by error log exports
        audit_enabled = any(log in log_exports for log in ['error', 'agent'])
        
        # Get option group settings
        option_group_settings = []
        if 'OptionGroupMemberships' in instance:
            for og in instance['OptionGroupMemberships']:
                options = rds_client.describe_option_groups(
                    OptionGroupName=og['OptionGroupName']
                )['OptionGroupsList'][0]['Options']
                option_group_settings.extend(options)
        
        # Check for audit-specific options
        audit_options = [opt for opt in option_group_settings if 'AUDIT' in opt['OptionName']]
        
        return {
            "audit_enabled": audit_enabled or bool(audit_options),
            "audit_config": {
                "cloudwatch_log_exports": log_exports,
                "audit_options": audit_options
            }
        }
        
    except Exception as e:
        return {
            "audit_enabled": False,
            "error": str(e)
        }

# Example usage
if __name__ == "__main__":
    # Check all instances
    log_disabled = []
    session = boto3.Session(profile_name='cdm_prd',region_name='us-west-2')
    all_results = check_rds_audit_logging(session)
    log_disabled.extend([db for db in all_results.keys() if all_results[db]['audit_enabled'] == False ])
    # print("All instances audit status:", all_results)
    print("Instances without audit logging: ", log_disabled)
    
    # Check specific instance
    # specific_result = check_rds_audit_logging()
    # print("Specific instance audit status:", specific_result)
