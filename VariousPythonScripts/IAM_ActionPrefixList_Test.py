import boto3
import json

def get_service_prefixes():
    iam = boto3.client('iam')
    
    # Get AWS managed policies that contain service actions
    policies = iam.list_policies(Scope='AWS', MaxItems=1000)
    
    service_prefixes = set()
    
    for policy in policies['Policies']:
        if 'PowerUser' in policy['PolicyName'] or 'ReadOnly' in policy['PolicyName']:
            policy_version = iam.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )
            
            document = policy_version['PolicyVersion']['Document']
            for statement in document.get('Statement', []):
                # Skip if statement is not a dictionary
                if not isinstance(statement, dict):
                    continue
                    
                action_list = statement.get('Action', [])
                not_action_list = statement.get('NotAction', [])
                
                # Ensure both are lists
                if isinstance(action_list, str):
                    action_list = [action_list]
                if isinstance(not_action_list, str):
                    not_action_list = [not_action_list]
                
                actions = action_list + not_action_list
                
                for action in actions:
                    if isinstance(action, str) and ':' in action:
                        prefix = action.split(':')[0]
                        service_prefixes.add(prefix)

    
    return sorted(list(service_prefixes))

prefixes = get_service_prefixes()
for prefix in prefixes:
    print(f"{prefix}:*")
