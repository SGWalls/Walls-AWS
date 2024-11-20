import boto3
from retriever import validate_sso_token

def vpc_association_check(response, target_vpc_id):
    """
    Check if a specific VPC ID exists in the response
    
    Args:
        response (dict): The response containing VPC information
        target_vpc_id (str): The VPC ID to search for
        
    Returns:
        bool: True if VPC ID is found, False otherwise
    """
    if 'VPCs' not in response:
        return False    
    return any(vpc['VPCId'] == target_vpc_id for vpc in response['VPCs'])

    

session = boto3.session.Session(profile_name='ops_tools')
validate_sso_token(session)
r53 = session.client('route53')

zone_id = input("Enter the Zone ID: ")
vpc_id = input("Enter the VPC ID: ")
region = input("Enter Region (Leave blank for us-west-2): ") or "us-west-2"
vpc_detail = {
    'VPCRegion':region,
    'VPCId': vpc_id
}
print("Checking for VPC Association authorization...")
if not vpc_association_check(r53.list_vpc_association_authorizations(HostedZoneId=zone_id), vpc_id):
    print("VPC not associated. . .")
    print("Creating VPC Association. . .")
    r53.create_vpc_association_authorization(
        HostedZoneId=zone_id,
        VPC=vpc_detail
    )
    print("Authorization Created.")
else:
    print("VPC Association authroization found!")
session = boto3.Session(profile_name='dev_kentico')
r53 = session.client('route53')
print("Associating VPC. . .")
r53.associate_vpc_with_hosted_zone(
    HostedZoneId=zone_id,
    VPC=vpc_detail
)
print("Complete")
# response = r53.get_hosted_zone(Id=zone_id)
# print(response)