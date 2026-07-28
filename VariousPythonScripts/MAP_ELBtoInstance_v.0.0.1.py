import boto3

session = boto3.Session(profile_name='prd_kentico',region_name='us-west-2')
elb = session.client('elbv2')
pub_lbs = {}
elb_list = [lb for lb in elb.describe_load_balancers()['LoadBalancers'] if lb.get('Scheme') == 'internet-facing']
accountId='166639160687'
tagging = session.client('resourcegroupstaggingapi')

def get_name(identifier,accountId):
    tagMappings = tagging.get_resources(
        ResourceARNList=[
            f'arn:aws:ec2:us-west-2:{accountId}:instance/{identifier}'
        ]
    )['ResourceTagMappingList']
    for tags in tagMappings:
        for tag in tags['Tags']:
            name=None
            if not name:
                name = tag['Value'] if (tag['Key'] == 'Name') else None
    return name



for loadBalancer in elb_list:
    pub_lbs[loadBalancer['LoadBalancerArn']] = {'Instances':[]}
    targetGroups = elb.describe_target_groups(LoadBalancerArn=loadBalancer['LoadBalancerArn'])['TargetGroups']

    for group in targetGroups:        
        tarHealthDescriptions = elb.describe_target_health(
                            TargetGroupArn=group['TargetGroupArn']
                            )['TargetHealthDescriptions']
        for target in tarHealthDescriptions:
            pub_lbs[loadBalancer['LoadBalancerArn']]['Instances'].append(get_name(target['Target']['Id'],accountId=accountId))

print(pub_lbs)