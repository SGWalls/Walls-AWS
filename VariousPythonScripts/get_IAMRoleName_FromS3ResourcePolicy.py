import profile
import boto3
import json
import time

start_time = time.time()

session = boto3.Session(profile_name="cdm_dev",region_name="us-west-2")
iam = session.resource('iam')
s3 = session.resource('s3')
bucket_policy = s3.BucketPolicy('tmk-cdm-data')
cond_list = [cond[0:21] for cond in json.loads(bucket_policy.policy)['Statement'][0]['Condition']['StringNotLike']['aws:userId'] if cond[0] == "A"] 
# role_list = iam.roles.all()
role_list = {k:v for k,v in [(role.role_id,role.role_name) 
                for role in iam.roles.all()]}
# user_list = iam.users.all()
user_list = {k:v for k,v in [(user.user_id,user.user_name) 
                for user in iam.users.all()]}
# iam.meta.client('iam').simulate_principal_policy(
#     PolicySourceArn='arn:aws:iam::896172592430:role/cdmdev_wsactuaries',
#     ActionNames=[
#         's3:GetObject',
#     ],
#     ResourceArns=[
#         'arn:aws:s3:::tmk-cdm-data/raw/lnl-mainframe/alis-cvfile/current/*',
#     ]
# )


def get_principal(identifier):
    if identifier[0:4] == "AROA":
        return role_list[identifier] 
    elif identifier[0:4] == "AIDA":
        return user_list[identifier]

principal_access = {}
for id in cond_list:
    principal_access[id] = get_principal(id)

print(principal_access)

print("---  %s seconds ---" % (time.time()- start_time))

