import boto3
import datetime

session = boto3.Session(profile_name='dev_devops',region_name='us-west-2')
ec2 = session.client('ec2')

paginator = ec2.get_paginator('describe_snapshots')
page_iterator = paginator.paginate(
    OwnerIds=[
        'self'
        ]
)
in_scope_snaps = []
for page in page_iterator:
    for snapshot in page['Snapshots']:
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if (current_time - snapshot['StartTime']).days > 10:
            in_scope_snaps.append(snapshot)
in_scope_snaps.count()