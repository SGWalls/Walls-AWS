import boto3
import json
import time
import os

def condition_check(statement_list):
    pr_list = []
    for statement in statement_list:
        try:
            pr_list.extend(statement['Condition']['StringNotLike']
            ['aws:userId'])        
        except KeyError:
            print('key error caught')
    return pr_list if pr_list else None


def write_file_out(data,filepath,filename):
    completeFilePath = os.path.join(filepath,filename)
    with open(completeFilePath,"w") as f:
        f.write(
            json.dumps(data,sort_keys=True,indent=4,default=str)
        )

bucket_name = input("Enter Bucket Name: ")
profile_name = input("Enter Profile Name: ")
export_path = input("Enter path for file export: ").replace("\\","\\\\")
export_name = input("Enter name for file export: ")
start_time = time.time()
session = boto3.Session(profile_name=profile_name,region_name="us-west-2")
iam = session.resource('iam')
s3 = session.resource('s3')
bucket_policy = s3.BucketPolicy(bucket_name)
cond_list = [cond[0:21] for cond in 
    condition_check(json.loads(bucket_policy.policy)['Statement']) 
    if cond[0] == "A"] 
principal_list = dict({k:v for k,v in [(role.role_id,role.role_name) 
                for role in iam.roles.all() if cond_list and 
                role.role_id in cond_list]}, 
                **{k:v for k,v in [(user.user_id,user.user_name) 
                for user in iam.users.all() if cond_list and
                user.user_id in cond_list]}
            )
write_file_out(principal_list,export_path,export_name)
print(principal_list)

print("---  %s seconds ---" % (time.time()- start_time))

# iam.meta.client('iam').simulate_principal_policy(
#     PolicySourceArn='placeholder',
#     ActionNames=[
#         's3:GetObject',
#     ],
#     ResourceArns=[
#         'placeholder',
#     ]
# )
