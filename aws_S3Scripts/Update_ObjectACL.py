import boto3

bucket = 'enterprise-waf-logs-113204598149-us-west-2'
auditGrant = {
    "Grantee":{
        "DisplayName":"AWS_GlobeLife_Audit",
        "ID":"91b482e2dae9c52cae85ea8d5c32a0d32b6d27e2bde703cb2a53108da89d64a8",
        "Type":"CanonicalUser"
    },
    "Permission":"READ"
}

session = boto3.Session(profile_name='log_arch',region_name='us-west-2')
s3 = session.client('s3')

paginator = s3.get_paginator('list_objects')
page_iterator = paginator.paginate(Bucket=bucket)
for page in page_iterator:
    
    for obj in page['Contents']:
        key = obj['Key']
        try:
            object_acl = s3.get_object_acl(
            Bucket=bucket,
            Key=key
            )
            if object_acl.get('ResponseMetadata'):
                object_acl.pop('ResponseMetadata')
            if auditGrant not in object_acl['Grants']:
                object_acl['Grants'].append(auditGrant)
        except Exception as e:
            print(e)
            print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
            raise e    
        if object_acl['Owner']['DisplayName'] != 'AWS_GlobeLife_Kentico_Prod': 
            print(object_acl)