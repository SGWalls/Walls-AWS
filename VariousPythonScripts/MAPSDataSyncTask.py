import boto3
import os
import time
import json
import logging
import pandas as pd
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError


session = boto3.session.Session(profile_name='prd_poly',region_name='us-west-2')
datasync = session.client('datasync')

env = input("environment (dev, tst, stg, or prd) : ").lower() 
bucketName = f'gl-cdm-{env}-polysystems'

s3Location = datasync.create_location_s3(
    Subdirectory='models/synced/',
    S3BucketArn=f'arn:aws:s3:::{bucketName}',
    S3StorageClass='STANDARD',
    S3Config={
        'BucketAccessRoleArn': 'arn:aws:iam::437833767532:role/Datasync_MAPS_S3Role'
    }
)

print(s3Location)
