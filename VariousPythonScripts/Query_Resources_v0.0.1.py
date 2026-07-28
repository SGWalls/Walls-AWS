import boto3
from retriever import Account
from retriever import get_org_account_list
from retriever import validate_sso_token

session = boto3.Session(profile_name="ct_master",region_name='us-west-2')

account_list = get_org_account_list(session)

excluded_patterns = [
    'AWSControlTower',
    'SSMQuickSetup'
]

def count_non_system_stacks(client):
    """
    Counts CloudFormation stacks that don't include specified system stack names.
    Returns the count of matching stacks.
    """
    excluded_patterns = [
        'AWSControlTower',
        'SSMQuickSetup'
    ]
    
    cf_client = client
    stack_count = 0
    
    try:
        paginator = cf_client.get_paginator('list_stacks')
        
        # Iterate through all stacks using pagination
        for page in paginator.paginate():
            for stack in page['StackSummaries']:
                # Check if stack name contains any of the excluded patterns
                if not any(pattern in stack['StackName'] for pattern in excluded_patterns):
                    # Only count stacks that are not DELETE_COMPLETE
                    if stack['StackStatus'] != 'DELETE_COMPLETE':
                        stack_count += 1
                        
        return stack_count
    
    except Exception as e:
        print(f"Error counting stacks: {str(e)}")
        return None

total_stacks = 0

for account in account_list:
    print(f"Counting stacks in account: {account['Id']}")
    account_stack_count = 0
    if account['Id'] == "662627786878":
        client = session.client('cloudformation')
        print(f"Starting count for account: {account['Id']}")
        account_stack_count = count_non_system_stacks(accnt.cloudformation)
        print(f"Stack count for account {account['Id']}: {account_stack_count}")
        total_stacks += account_stack_count
    else:
        accnt = Account(account_id=account['Id'], sessionName='ResourceQuery', session=session, region='us-west-2')
        accnt.cloudformation = accnt.client_config('cloudformation')
        # stack_list = []
        # stacks = accnt.cloudformation.list_stacks()
        # stack_list.extend(stack for stack in stacks['StackSummaries'] 
        #                   if not any(pattern in stack['StackName'] for 
        #                              pattern in excluded_patterns)
        #                  and stack['StackStatus'] != 'DELETE_COMPLETE')
        # while 'NextToken' in stacks:
        #     stacks = accnt.cloudformation.list_stacks(NextToken=stacks['NextToken'])
        #     stack_list.extend(stacks['StackSummaries'])
        print(f"Starting count for account: {account['Id']}")
        account_stack_count = count_non_system_stacks(accnt.cloudformation)
        print(f"Stack count for account {account['Id']}: {account_stack_count}")
        total_stacks += account_stack_count
    
print(f"Total stacks: {total_stacks}")