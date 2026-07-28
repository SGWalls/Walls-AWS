import boto3
import inquirer

# Ask user to chose an IPAM pool from a list of available IPAM pools using inquirer 
def get_ipam_pool_id(client):
    ipam_pools = client.describe_ipam_pools()['IpamPools']
    # validate there are ipam pools available and provide a message if there are none
    if not ipam_pools:
        print("No IPAM pools available.")
        return None
    pool_choices = [pool['IpamPoolId'] for pool in ipam_pools]
    pool_question = [
        inquirer.List('Ipv4IpamPoolId',
                      message="Choose an IPAM pool",
                      choices=pool_choices,
                      ),
        inquirer.Text('Ipv4NetmaskLength',
                      message="Enter the netmask length for the VPC",
                      default='25'),
    ]
    return inquirer.prompt(pool_question)


def get_vpc_parameters(client):
    vpc_question = [
        inquirer.List('use_ipam_pool',
                      message="Do you want to use an IPv4 IPAM Pool ID or define the CIDR block manually?",
                      choices=['Use IPAM Pool ID', 'Define CIDR block']),
    ]
    vpc_answers = inquirer.prompt(vpc_question)    
    if vpc_answers['use_ipam_pool'] == 'Define CIDR block':
        cidr_question = [
            inquirer.Text('CidrBlock', message="Enter the CIDR block for the VPC"),
        ]
        cidr_answer = inquirer.prompt(cidr_question)
        vpc_answers.update(cidr_answer)
    else:
        ipam_pool_answer = get_ipam_pool_id(client)
        vpc_answers.update(ipam_pool_answer)
    additional_questions = [
        inquirer.List(
            'InstanceTenancy', 
            message="Choose the instance tenancy for the VPC",
            choices=[
                'default', 
                'dedicated', 
                'host'
            ],
            default='default')
    ]
    additional_answers = inquirer.prompt(additional_questions)
    vpc_answers.update(additional_answers)
    vpc_answers.pop('use_ipam_pool')
    return vpc_answers


def create_vpc(client, **kwargs):
    try:
        response = client.create_vpc(**kwargs)
        vpc_id = response['Vpc']['VpcId']
        print(f"VPC created with ID: {vpc_id}")
    except Exception as e:
        print(f"Error creating VPC: {e}")
    return response


def get_subnet_parameters(client, vpc_configuration):
    # determine if vpc is configured to use an ipam pool. If so, set the same Ipv4IpamPoolId for the subenet parameters.
    if 'Ipv4IpamPoolId' in vpc_configuration:
        ipv4IpamPoolId = vpc_configuration['Ipv4IpamPoolId']


def create_subnet(client, vpc_id, availability_zone ,ipv4IpamPoolId=None, ipv4netmaskLength=None, cidr_block=None, **kwargs):
    try:
        response = client.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=availability_zone
        )
        subnet_id = response['Subnet']['SubnetId']
        print(f"Subnet created with ID: {subnet_id} in AZ: {availability_zone}")
    except Exception as e:
        print(f"Error creating subnet: {e}")
    return response