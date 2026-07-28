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
    Each CIDR IP is treated as a separate rule for accurate comparison regardless of order.
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

    def expand_rules(security_group: dict) -> tuple[list, list]:
        """
        Expands security group rules so each CIDR IP is a separate rule.
        Returns tuple of (inbound_rules, outbound_rules)
        """
        inbound_rules = []
        outbound_rules = []

        # Process inbound rules
        for rule in security_group['IpPermissions']:
            base_rule = {
                'protocol': rule.get('IpProtocol', '-1'),
                'from_port': rule.get('FromPort', -1),
                'to_port': rule.get('ToPort', -1),
            }
            
            # Handle IPv4 ranges
            for ip_range in rule.get('IpRanges', []):
                new_rule = base_rule.copy()
                new_rule['cidr'] = ip_range['CidrIp']
                new_rule['type'] = 'IPv4'
                inbound_rules.append(new_rule)

            # Handle IPv6 ranges
            for ip_range in rule.get('Ipv6Ranges', []):
                new_rule = base_rule.copy()
                new_rule['cidr'] = ip_range['CidrIpv6']
                new_rule['type'] = 'IPv6'
                inbound_rules.append(new_rule)

            # Handle security group references
            for group in rule.get('UserIdGroupPairs', []):
                new_rule = base_rule.copy()
                new_rule['referenced_group'] = group['GroupId']
                new_rule['type'] = 'SecurityGroup'
                inbound_rules.append(new_rule)

        # Process outbound rules
        for rule in security_group['IpPermissionsEgress']:
            base_rule = {
                'protocol': rule.get('IpProtocol', '-1'),
                'from_port': rule.get('FromPort', -1),
                'to_port': rule.get('ToPort', -1),
            }
            
            # Handle IPv4 ranges
            for ip_range in rule.get('IpRanges', []):
                new_rule = base_rule.copy()
                new_rule['cidr'] = ip_range['CidrIp']
                new_rule['type'] = 'IPv4'
                outbound_rules.append(new_rule)

            # Handle IPv6 ranges
            for ip_range in rule.get('Ipv6Ranges', []):
                new_rule = base_rule.copy()
                new_rule['cidr'] = ip_range['CidrIpv6']
                new_rule['type'] = 'IPv6'
                outbound_rules.append(new_rule)

            # Handle security group references
            for group in rule.get('UserIdGroupPairs', []):
                new_rule = base_rule.copy()
                new_rule['referenced_group'] = group['GroupId']
                new_rule['type'] = 'SecurityGroup'
                outbound_rules.append(new_rule)

        return inbound_rules, outbound_rules

    def compare_rules(sg1: dict, sg2: dict) -> dict:
        """Compare rules between two security groups"""
        sg1_inbound, sg1_outbound = expand_rules(sg1)
        sg2_inbound, sg2_outbound = expand_rules(sg2)

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
    "FMManagedSecurityGroupc3fbdb88-1d07-44f7-a165-d34215cd3091-sg-074615d0a09de8723",
    "FMManagedSecurityGroupc3fbdb88-1d07-44f7-a165-d34215cd3091-sg-0c4d0e785733c3bc5"
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