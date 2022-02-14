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


def resource_check(statement,target_value):    
    try:
        if isinstance(statement['Resource'],list):
            return (
            any(
                (
                    target_value in string 
                    for 
                    string in statement['Resource']
                ) 
                or 
                (
                    ("*" in statement['Resource']) 
                    and 
                    (
                        ("s3:" in string for string in statement['Action'])
                        if 
                        isinstance(statement['Action'],list) 
                        else 
                        ("s3:" in statement['Action'])
                    )   
                )
            )
        )        
        else:
            return (
                target_value in statement['Resource'] 
                or 
                (
                    statement['Resource'] == "*"
                    and 
                    (
                        ("s3:" in string for string in statement['Action'])
                        if 
                        isinstance(statement['Action'],list) 
                        else 
                        ("s3:" in statement['Action'])
                    )   
                )
            )
    except KeyError:
        if isinstance(statement['NotResource'],list):
            return (
            any(
                    (
                        (
                            ("s3:" in item for item in statement['Action']) 
                            or 
                            ( "*" in statement['Action'])
                        ) 
                        and 
                        (
                            target_value not in string 
                            for string in 
                            statement['NotResource']
                        )
                    )                             
                    or 
                    (
                        ("*" in statement['NotResource']) 
                        and 
                        ("s3:" not in item for item in statement['Action'])
                    )
                )
            )        
        else:
            return (
                (
                    (
                        "s3:" in item for item in statement['Action']
                    ) 
                    and 
                    (
                        target_value not in statement['NotResource']
                    )
                ) #or 
                    # (("s3:" not in item for item in statement['Action']) and
                    #  (statement['NotResource'] == "*"))
            )
        


def write_file_out(data,filepath,filename):
    completeFilePath = os.path.join(filepath,filename)
    with open(completeFilePath,"w") as f:
        f.write(
            json.dumps(data,sort_keys=True,indent=4,default=str)
        )
profile_name = input("Enter Profile Name: ")
session = boto3.Session(profile_name=profile_name,region_name="us-west-2")
iam = session.resource('iam')
s3 = session.resource('s3')
while True:
    try:
        bucket_name = input("Enter Bucket Name: ")
        bucket_policy = s3.BucketPolicy(bucket_name).policy
    except s3.meta.client.exceptions.NoSuchBucket:
        print('!!! Invalid Bucket Name !!!')
    else:
        break
# export_path = input("Enter path for file export: ").replace("\\","\\\\")
# export_name = input("Enter name for file export: ")
start_time = time.time()
cond_list = [cond[0:21] for cond in 
    condition_check(json.loads(bucket_policy)['Statement']) 
    if cond[0] == "A"] 
principal_list = dict({k:v for k,v in [(role.role_id,role.role_name) 
                for role in iam.roles.all() if cond_list and 
                role.role_id in cond_list]}, 
                **{k:v for k,v in [(user.user_id,user.user_name) 
                for user in iam.users.all() if cond_list and
                user.user_id in cond_list]}
            )
policy_list = iam.policies.filter(
    Scope='All',
    OnlyAttached=True,
    PolicyUsageFilter='PermissionsPolicy'
)
for policy in policy_list:
    access_switch = False
    policy_doc = policy.default_version.document
    if isinstance(policy_doc['Statement'],list):
        for statements in policy_doc['Statement']:
            access_switch = resource_check(statements,bucket_name)
    else:
        access_switch = resource_check(statements,bucket_name)    
    if access_switch:
        print(f"policy named: {policy.policy_name} has access to the target")
# write_file_out(principal_list,export_path,export_name)
# print(principal_list)

print("---  %s seconds ---" % (time.time()- start_time))

# for statements in json.loads(bucket_policy)['Statement']:
#     print(resource_check(statements,bucket_name))
# iam.meta.client('iam').simulate_principal_policy(
#     PolicySourceArn='placeholder',
#     ActionNames=[
#         's3:GetObject',
#     ],
#     ResourceArns=[
#         'placeholder',
#     ]
# )
