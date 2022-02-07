import boto3


def get_ipranges(ipblocks):
    ipranges=[]
    for ipblock in ipblocks:
        iprange = {
            'CidrIp': ipblock,
            'Description': f'Allows access from {ipblock}'
        }
        ipranges.append(iprange)
    return ipranges

session = boto3.session.Session(profile_name="cdm_tst",region_name="us-west-2")
ec2 = session.client('ec2')
vpc_id = input('Enter VPC ID: ')
group_name = input('Enter a Name for the Security Group: ')
ipRange_list = input('Enter a list of IP Ranges to be allowed: ')
ipRange_list.split(',')
ingress_permission = [
    {
        'FromPort': 443,
        'IpProtocol':'tcp',
        'IpRanges': get_ipranges(ipRange_list),
        'ToPort': 443        
    }
]

new_group = ec2.create_security_group(
        Description='Allows Access to State Machine VPC endpoint.',
        GroupName=group_name,
        VpcId=vpc_id
    )

ec2.authorize_security_group_ingress(
    GroupId=new_group['GroupId'],
    IpPermissions=ingress_permission
)