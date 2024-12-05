import boto3
import concurrent.futures
from retriever import Account
from retriever import get_org_account_list
from retriever import validate_sso_token

def count_non_system_stacks(client):
    """
    Counts CloudFormation stacks that don't include specified system stack names.
    Returns the count of matching stacks.
    """
    excluded_patterns = [
        'AWSControlTower',
        'SSMQuickSetup'
    ]
    
    stack_count = 0
    
    try:
        paginator = client.get_paginator('list_stacks')
        for page in paginator.paginate():
            # Filter stacks in a list comprehension for better performance
            valid_stacks = [
                stack for stack in page['StackSummaries']
                if not any(pattern in stack['StackName'] for pattern in excluded_patterns)
                and stack['StackStatus'] != 'DELETE_COMPLETE'
            ]
            stack_count += len(valid_stacks)
                        
        return stack_count
    
    except Exception as e:
        print(f"Error counting stacks: {str(e)}")
        return 0

def process_account(account, session):
    """
    Process a single account and return its stack count
    """
    try:
        print(f"Starting count for account: {account['Id']}")
        
        if account['Id'] == "662627786878":
            client = session.client('cloudformation')
        else:
            accnt = Account(account_id=account['Id'], 
                          sessionName='ResourceQuery', 
                          session=session, 
                          region='us-west-2')
            accnt.cloudformation = accnt.client_config('cloudformation')
            client = accnt.cloudformation
            
        account_stack_count = count_non_system_stacks(client)
        print(f"Stack count for account {account['Id']}: {account_stack_count}")
        return account_stack_count
        
    except Exception as e:
        print(f"Error processing account {account['Id']}: {str(e)}")
        return 0

def main():
    session = boto3.Session(profile_name="ct_master", region_name='us-west-2')
    account_list = get_org_account_list(session)
    total_stacks = 0
    
    # Process accounts in parallel using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Create future tasks for each account
        future_to_account = {
            executor.submit(process_account, account, session): account 
            for account in account_list
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_account):
            account = future_to_account[future]
            try:
                stack_count = future.result()
                total_stacks += stack_count
            except Exception as e:
                print(f"Account {account['Id']} generated an exception: {str(e)}")
    
    print(f"Total stacks across all accounts: {total_stacks}")

if __name__ == "__main__":
    main()
