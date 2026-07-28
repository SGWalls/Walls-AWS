import boto3
import os
import datetime
import logging
from botocore.exceptions import ClientError
from retriever import validate_sso_token, get_org_account_list

LOG_LEVEL = 'INFO'

userprofile = os.environ["USERPROFILE"]
log_path = os.path.dirname(
        f"{userprofile}\\Documents\\AWS_Projects\\Scripts\\Python\\"
         "logging\\EC2_FMM_SecGroupCompare\\"
    )
log_file_name = f"ec2-FMMSecGroupCompare-{datetime.datetime.now().strftime('%Y%m%d_%H.%M.%S')}.log"
if not os.path.exists(log_path):
    os.makedirs(log_path)

def compare_security_groups_by_prefix(ec2_client, prefix1: str, prefix2: str) -> dict:
    """
    Compare security groups that match two different prefixes and identify differences in their rules.
    
    Args:
        ec2_client: boto3 EC2 client
        prefix1 (str): First security group name prefix to compare
        prefix2 (str): Second security group name prefix to compare
        
    Returns:
        dict: Dictionary containing the comparison results
    """
    def get_sg_by_prefix(prefix: str) -> dict:
        try:
            response = ec2_client.describe_security_groups(
                Filters=[{
                    'Name': 'group-name',
                    'Values': [f'{prefix}*']
                }]
            )
            if response['SecurityGroups']:
                return response['SecurityGroups'][0]
            return None
        except ClientError as e:
            logger.error(f"Error retrieving security group with prefix {prefix}: {e}")
            return None

    def format_rule(rule: dict) -> dict:
        """Format a security group rule for comparison"""
        formatted_rule = {
            'protocol': rule.get('IpProtocol', ''),
            'from_port': rule.get('FromPort', ''),
            'to_port': rule.get('ToPort', ''),
            'cidr_ranges': [],
            'security_groups': []
        }
        
        # Add IPv4 CIDR ranges
        if 'IpRanges' in rule:
            formatted_rule['cidr_ranges'].extend(
                [ip_range['CidrIp'] for ip_range in rule['IpRanges']]
            )
            
        # Add IPv6 CIDR ranges
        if 'Ipv6Ranges' in rule:
            formatted_rule['cidr_ranges'].extend(
                [ip_range['CidrIpv6'] for ip_range in rule['Ipv6Ranges']]
            )
            
        # Add referenced security groups
        if 'UserIdGroupPairs' in rule:
            formatted_rule['security_groups'].extend(
                [group['GroupId'] for group in rule['UserIdGroupPairs']]
            )
            
        return formatted_rule

    def compare_rules(sg1: dict, sg2: dict) -> dict:
        """Compare rules between two security groups"""
        differences = {
            'name_comparison': {
                'sg1_name': sg1['GroupName'],
                'sg2_name': sg2['GroupName']
            },
            'inbound_rules': {
                'sg1_only': [],
                'sg2_only': [],
                'matching': []
            },
            'outbound_rules': {
                'sg1_only': [],
                'sg2_only': [],
                'matching': []
            }
        }

        # Format rules for comparison
        sg1_inbound = [format_rule(rule) for rule in sg1['IpPermissions']]
        sg2_inbound = [format_rule(rule) for rule in sg2['IpPermissions']]
        sg1_outbound = [format_rule(rule) for rule in sg1['IpPermissionsEgress']]
        sg2_outbound = [format_rule(rule) for rule in sg2['IpPermissionsEgress']]

        # Compare inbound rules
        for rule in sg1_inbound:
            if rule in sg2_inbound:
                differences['inbound_rules']['matching'].append(rule)
            else:
                differences['inbound_rules']['sg1_only'].append(rule)

        for rule in sg2_inbound:
            if rule not in sg1_inbound:
                differences['inbound_rules']['sg2_only'].append(rule)

        # Compare outbound rules
        for rule in sg1_outbound:
            if rule in sg2_outbound:
                differences['outbound_rules']['matching'].append(rule)
            else:
                differences['outbound_rules']['sg1_only'].append(rule)

        for rule in sg2_outbound:
            if rule not in sg1_outbound:
                differences['outbound_rules']['sg2_only'].append(rule)

        return differences

    # Get security groups by prefix
    sg1 = get_sg_by_prefix(prefix1)
    sg2 = get_sg_by_prefix(prefix2)

    # Handle cases where security groups are not found
    if not sg1 and not sg2:
        return {"error": f"No security groups found with prefixes {prefix1} or {prefix2}"}
    elif not sg1:
        return {"error": f"No security group found with prefix {prefix1}"}
    elif not sg2:
        return {"error": f"No security group found with prefix {prefix2}"}

    # Compare the security groups
    comparison_results = compare_rules(sg1, sg2)
    
    # Add summary of differences
    comparison_results['summary'] = {
        'has_inbound_differences': bool(comparison_results['inbound_rules']['sg1_only'] or 
                                      comparison_results['inbound_rules']['sg2_only']),
        'has_outbound_differences': bool(comparison_results['outbound_rules']['sg1_only'] or 
                                       comparison_results['outbound_rules']['sg2_only']),
        'total_differences': (len(comparison_results['inbound_rules']['sg1_only']) + 
                            len(comparison_results['inbound_rules']['sg2_only']) +
                            len(comparison_results['outbound_rules']['sg1_only']) + 
                            len(comparison_results['outbound_rules']['sg2_only']))
    }

    return comparison_results

def create_logger(logger_name,log_path,log_file_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(LOG_LEVEL)
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

logger = create_logger('FMMSGCompare',log_path,log_file_name)

session = boto3.Session(profile_name='dev_poly')
validate_sso_token(session)
ec2 = session.client('ec2')

results = compare_security_groups_by_prefix(
    ec2,
    "FMManagedSecurityGroup17859c5e-6e22-4f48-9f36-c5d1104e2446-sg-03f983933483da9ca",
    "FMManagedSecurityGroup17859c5e-6e22-4f48-9f36-c5d1104e2446-sg-0c6317495f7e7c086"
)

if 'error' in results:
    logger.info(f"Error: {results['error']}")
else:
    logger.info(f"\nComparison of security groups:")
    logger.info(f"SG1: {results['name_comparison']['sg1_name']}")
    logger.info(f"SG2: {results['name_comparison']['sg2_name']}")
    
    logger.info("\nSummary:")
    logger.info(f"Total differences found: {results['summary']['total_differences']}")
    logger.info(f"Has inbound differences: {results['summary']['has_inbound_differences']}")
    logger.info(f"Has outbound differences: {results['summary']['has_outbound_differences']}")
    
    if results['inbound_rules']['sg1_only']:
        logger.info("\nInbound rules only in SG1:")
        for rule in results['inbound_rules']['sg1_only']:
            logger.info(rule)
            
    if results['inbound_rules']['sg2_only']:
        logger.info("\nInbound rules only in SG2:")
        for rule in results['inbound_rules']['sg2_only']:
            logger.info(rule)
            
    if results['outbound_rules']['sg1_only']:
        logger.info("\nOutbound rules only in SG1:")
        for rule in results['outbound_rules']['sg1_only']:
            logger.info(rule)
            
    if results['outbound_rules']['sg2_only']:
        logger.info("\nOutbound rules only in SG2:")
        for rule in results['outbound_rules']['sg2_only']:
            logger.info(rule)