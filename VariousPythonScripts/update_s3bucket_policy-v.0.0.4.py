import boto3
import json
from botocore.exceptions import ClientError

def condition_check(statement, ConditionOperator='StringNotEquals', 
                     ConditionKey='aws:SourceVpce', 
                     ConditionValue='vpce-0557b53fda44db465'):
    try:
        vpce_conditon = statement['Condition'][ConditionOperator][ConditionKey]
        if vpce_conditon and ConditionValue not in vpce_conditon:            
            return vpce_conditon
            buckets_w_policy.append(bucket['Name'])
            # bucket_pol['Statement'][0]['Condition']['StringNotEquals']['aws:SourceVpce'].append("")
    except KeyError:
        return False


def convert_to_list(string):
    return list(string.split())

def check_key(i_dict, i_key):
    return i_dict.get(i_key)


def update_condition(statement, ConditionOperator='StringNotEquals', 
                     ConditionKey='aws:SourceVpce', 
                     ConditionValue='vpce-0557b53fda44db465'):
    # print(statement)
    try:
        statement['Condition'][ConditionOperator][ConditionKey].append(ConditionValue)
    except KeyError as e:
        statement['Condition'][ConditionOperator] = {ConditionKey: [ConditionValue]}
    except AttributeError as e:
        if "'str' object has no attribute 'append'" in str(e):
            statement['Condition'][ConditionOperator][ConditionKey] = statement['Condition'][ConditionOperator][ConditionKey].split()
            statement['Condition'][ConditionOperator][ConditionKey].append(ConditionValue)
    # print(statement)
    return statement


session = boto3.session.Session(profile_name='cdm_dev',region_name='us-west-2')
s3 = session.client('s3')
buckets_w_policy = []
bucket_list = s3.list_buckets()['Buckets']
for bucket in bucket_list:
    try:
        bucket_pol = s3.get_bucket_policy(Bucket=bucket['Name'])['Policy']
    except ClientError as e:
        print("Bucket has no Policy.")
        continue
    bucket_pol = json.loads(bucket_pol) if bucket_pol else {'Statement': []}
    print(bucket_pol)
    for statement in bucket_pol['Statement']:
        if (statement['Effect'] == "Deny" and statement['Action'] == "s3:*"
         and (statement['Principal'] == "*" or (
         type(statement['Principal']) is dict) and 
         statement['Principal'].get('AWS') == "*")):
            result = condition_check(statement)
            if result:
                statement.update(update_condition(statement))
                buckets_w_policy.append(bucket['Name'])
                policy_change = True
                break
            result = condition_check(statement,"StringNotLike","aws:PrincipalArn", "arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/*")
            if not result:
                # print(statement)
                statement.update(update_condition(statement,"StringNotLike","aws:PrincipalArn", "arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/*"))
                policy_change = True
    bucket_policy = json.dumps(bucket_pol)
    if policy_change:
        print(bucket_pol)
        pass
    # try:
    #     vpce_conditon = bucket_pol['Statement'][0]['Condition']['StringNotEquals']['aws:SourceVpce']
    #     if vpce_conditon and "vpce-0d4823ea4d53b583b" not in vpce_conditon:
    #         buckets_w_policy.append(bucket['Name'])
    #         # bucket_pol['Statement'][0]['Condition']['StringNotEquals']['aws:SourceVpce'].append("")
    # except KeyError:
    #     pass
print(buckets_w_policy)


