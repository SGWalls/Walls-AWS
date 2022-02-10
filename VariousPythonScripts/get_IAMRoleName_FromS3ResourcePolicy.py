import profile
import boto3
import json
import time


def condition_check(statement_list):
    pr_list = []
    for statement in statement_list:
        try:
            pr_list.extend(statement['Condition']['StringNotLike']
            ['aws:userId'])        
        except KeyError:
            print('key error caught')
    return pr_list


start_time = time.time()

session = boto3.Session(profile_name="cdm_dev",region_name="us-west-2")
iam = session.resource('iam')
s3 = session.resource('s3')
bucket_policy = s3.BucketPolicy('tmk-cdm-data')
try:
    cond_list = [cond[0:21] for cond in 
    condition_check(json.loads(bucket_policy.policy)['Statement']) if cond[0] == "A"] 
except KeyError:
    cond_list = None
principal_list = dict({k:v for k,v in [(role.role_id,role.role_name) 
                for role in iam.roles.all() if cond_list and 
                role.role_id in cond_list]}, 
                **{k:v for k,v in [(user.user_id,user.user_name) 
                for user in iam.users.all() if cond_list and
                user.user_id in cond_list]}
            )

print(principal_list)

print("---  %s seconds ---" % (time.time()- start_time))

# iam.meta.client('iam').simulate_principal_policy(
#     PolicySourceArn='arn:aws:iam::896172592430:role/cdmdev_wsactuaries',
#     ActionNames=[
#         's3:GetObject',
#     ],
#     ResourceArns=[
#         'arn:aws:s3:::tmk-cdm-data/raw/lnl-mainframe/alis-cvfile/current/*',
#     ]
# )
