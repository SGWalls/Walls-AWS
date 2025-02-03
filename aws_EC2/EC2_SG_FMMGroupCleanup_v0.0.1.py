import boto3
from botocore.exceptions import ClientError
from typing import List

def remove_security_groups_from_nic(network_interface_id: str, security_group_ids: List[str]) -> tuple[bool, List[str]]:
    """
    Removes specified security groups from a network interface if they are attached.
    
    Args:
        network_interface_id (str): The ID of the network interface
        security_group_ids (List[str]): List of security group IDs to remove
        
    Returns:
        tuple[bool, List[str]]: 
            - Boolean indicating if any changes were made
            - List of security group IDs that were actually removed
            
    Raises:
        ClientError: If there's an AWS API error
        ValueError: If removing groups would leave interface with no security groups
    """
    try:
        ec2_client = boto3.client('ec2')
        
        # Get current security groups attached to the network interface
        response = ec2_client.describe_network_interfaces(
            NetworkInterfaceIds=[network_interface_id]
        )
        
        if not response['NetworkInterfaces']:
            raise ValueError(f"Network interface {network_interface_id} not found")
            
        current_groups = response['NetworkInterfaces'][0]['Groups']
        current_group_ids = [group['GroupId'] for group in current_groups]
        
        # Find which of the specified groups are actually attached
        groups_to_remove = set(security_group_ids) & set(current_group_ids)
        
        # If none of the specified groups are attached, return early
        if not groups_to_remove:
            return False, []
            
        # Calculate the new group list
        new_groups = [gid for gid in current_group_ids if gid not in groups_to_remove]
        
        # Check if removing these groups would leave the interface with no security groups
        if not new_groups:
            raise ValueError(
                "Cannot remove all specified security groups as it would leave the "
                "network interface with no security groups attached"
            )
            
        # Update the network interface with the new security group list
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=network_interface_id,
            Groups=new_groups
        )
        
        return True, list(groups_to_remove)
        
    except ClientError as e:
        print(f"Error removing security groups: {e}")
        raise

sg_prefix_list = [
    'FMManagedSecurityGroupc3fbdb88-1d07-44f7-a165-d34215cd3091-sg-0c4d0e785733c3bc5',
    'FMManagedSecurityGroup7f18d228-83d5-41aa-94fb-cefbfc910fa2-sg-0f662a01416598838',
    'FMManagedFMManagedSecurityGroup17859c5e-6e22-4f48-9f36-c5d1104e2446-sg-0c6317495f7e7c086'
]

session = boto3.Session(profile_name='tst_eclaims',region_name='us-west-2')
ec2 = session.client('ec2')

response = ec2.describe_security_groups()
sg_list = response["SecurityGroups"]
while "NextToken" in response:
        response = ec2.describe_security_groups(NextToken=response['NextToken'])
        sg_list.extend(response["SecurityGroups"])

sg_prefix_list = [
    "FMManagedSecurityGroup17859c5e-6e22-4f48-9f36-c5d1104e2446-sg-03f983933483da9ca",
    "FMManagedSecurityGroup44667565-8b31-4310-adbc-0235a288cacc-sg-07240bb9c495f4821",
    "FMManagedSecurityGroupc3fbdb88-1d07-44f7-a165-d34215cd3091-sg-074615d0a09de8723",
    "FMManagedSecurityGroup15412b96-8036-4027-9306-c9b9e5b7bd77-sg-0da01e18e277c29f7"
]
sg_final_list = [sg for sg in sg_list if sg['GroupName'][:79] in sg_prefix_list]
sg_final_dict = {sg['GroupId']:sg['GroupName'] for sg in sg_list if sg['GroupName'][:79] in sg_prefix_list}
print(sg_final_dict)
network_attachments = ec2.describe_network_interfaces()
nic_list = network_attachments["NetworkInterfaces"]
while "NextToken" in network_attachments:
        network_attachments = ec2.describe_network_interfaces(NextToken=network_attachments['NextToken'])
        nic_list.extend(network_attachments["NetworkInterfaces"])
        

# for sg in sg_list:
#     if sg["GroupName"].startswith("FMManagedSecurityGroup"):
#         if sg["GroupName"] not in sg_prefix_list:
#             print(sg["GroupName"])