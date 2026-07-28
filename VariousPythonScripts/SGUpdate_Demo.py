import boto3

# Function to modify security group
def modify_sg(sg_id, fromPort, to):
    ec2 = boto3.client('ec2')
    try:
        data = ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ])
        print('Ingress Successfully Set', data)
    except Exception as e:
        print('ERROR', e)


import boto3

class SecurityGroupManager:
    def __init__(self, security_group_id):
        self.security_group_id = security_group_id
        self.ec2 = boto3.client('ec2')

    def modify_security_group(self, from_port, to_port):
        try:
            data = self.ec2.authorize_security_group_ingress(
                GroupId=self.security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': from_port,
                        'ToPort': to_port,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            print('Ingress Successfully Set', data)
        except Exception as e:
            print('ERROR', e)
