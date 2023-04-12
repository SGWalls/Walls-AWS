import boto3
import os
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']


class Account:
    def __init__(self, account_id=None, session=None, region="us-west-2"):
        self.region = region
        self.session = session if session else boto3
        self.account_id = account_id 
        self.credentials = self.get_credentials()

    def get_credentials(self):
        return self.assume_role('ent_setS3AccountPubBlock')

    def assume_role(self, session_name, 
                    role_name="AWSControlTowerExecution", 
                    duration=900):        
        response = self.session.client('sts').assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{role_name}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self, service):
        return self.session.client(
            service_name=service,
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name = self.region,
        )

    def s3_account_pab(self):
        s3control = self.client_config('s3control')
        try:
            publicAccessSetting =  s3control.get_public_access_block(
                AccountId=self.account_id
            )['PublicAccessBlockConfiguration']
        except s3control.exceptions.NoSuchPublicAccessBlockConfiguration as e:
            logger.info("Account does not have any Public Access Block configurations")
            publicAccessSetting = {
                    'PublicAccessBlock': False                
            }
        if not all(publicAccessSetting.values()):
            logger.info("Putting Public Access Block. . .")
            s3control.put_public_access_block(
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                },
                AccountId=self.account_id
            )
        else:
            logger.info("Public Access Block Already Enabled.")
        return


def delimiter(symbol='='):
    logger.info(symbol * 120)

serviceName = input("Name of the Service needing an endpoint: ")
service = f"com.amazonaws.{region}.{serviceName}"

    ec2.create_vpc_endpoint(
        DryRun=True|False,
        VpcEndpointType='Interface'|'Gateway'|'GatewayLoadBalancer',
        VpcId='string',
        ServiceName='string',
        PolicyDocument='string',
        RouteTableIds=[
            'string',
        ],
        SubnetIds=[
            'string',
        ],
        SecurityGroupIds=[
            'string',
        ],
        IpAddressType='ipv4'|'dualstack'|'ipv6',
        DnsOptions={
            'DnsRecordIpType': 'ipv4'|'dualstack'|'ipv6'|'service-defined'
        },
        ClientToken='string',
        PrivateDnsEnabled=True|False,
        TagSpecifications=[
            {
                'ResourceType': 'capacity-reservation'|'client-vpn-endpoint'|'customer-gateway'|'carrier-gateway'|'coip-pool'|'dedicated-host'|'dhcp-options'|'egress-only-internet-gateway'|'elastic-ip'|'elastic-gpu'|'export-image-task'|'export-instance-task'|'fleet'|'fpga-image'|'host-reservation'|'image'|'import-image-task'|'import-snapshot-task'|'instance'|'instance-event-window'|'internet-gateway'|'ipam'|'ipam-pool'|'ipam-scope'|'ipv4pool-ec2'|'ipv6pool-ec2'|'key-pair'|'launch-template'|'local-gateway'|'local-gateway-route-table'|'local-gateway-virtual-interface'|'local-gateway-virtual-interface-group'|'local-gateway-route-table-vpc-association'|'local-gateway-route-table-virtual-interface-group-association'|'natgateway'|'network-acl'|'network-interface'|'network-insights-analysis'|'network-insights-path'|'network-insights-access-scope'|'network-insights-access-scope-analysis'|'placement-group'|'prefix-list'|'replace-root-volume-task'|'reserved-instances'|'route-table'|'security-group'|'security-group-rule'|'snapshot'|'spot-fleet-request'|'spot-instances-request'|'subnet'|'subnet-cidr-reservation'|'traffic-mirror-filter'|'traffic-mirror-session'|'traffic-mirror-target'|'transit-gateway'|'transit-gateway-attachment'|'transit-gateway-connect-peer'|'transit-gateway-multicast-domain'|'transit-gateway-policy-table'|'transit-gateway-route-table'|'transit-gateway-route-table-announcement'|'volume'|'vpc'|'vpc-endpoint'|'vpc-endpoint-connection'|'vpc-endpoint-service'|'vpc-endpoint-service-permission'|'vpc-peering-connection'|'vpn-connection'|'vpn-gateway'|'vpc-flow-log'|'capacity-reservation-fleet'|'traffic-mirror-filter-rule'|'vpc-endpoint-connection-device-type'|'verified-access-instance'|'verified-access-group'|'verified-access-endpoint'|'verified-access-policy'|'verified-access-trust-provider'|'vpn-connection-device-type'|'vpc-block-public-access-exclusion'|'ipam-resource-discovery'|'ipam-resource-discovery-association',
                'Tags': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                ]
            },
        ]
    )