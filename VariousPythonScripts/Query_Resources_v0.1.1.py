import boto3
import concurrent.futures
from retriever import Account
from retriever import get_org_account_list
from retriever import validate_sso_token

def count_batch_jobs(client):
    """
    Counts all AWS Batch jobs in an account.
    Returns the total count of jobs.
    """
    job_count = 0
    
    try:
        # Get all job queues first
        job_queues = []
        paginator = client.get_paginator('describe_job_queues')
        for page in paginator.paginate():
            job_queues.extend([queue['jobQueueArn'] for queue in page['jobQueues']])

        # For each queue, get job counts for all job statuses
        job_statuses = ['SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 
                       'RUNNING', 'SUCCEEDED']
        
        for queue in job_queues:
            for status in job_statuses:
                paginator = client.get_paginator('list_jobs')
                for page in paginator.paginate(jobQueue=queue, jobStatus=status):
                    job_count += len(page['jobSummaryList'])
                        
        return job_count
    
    except Exception as e:
        print(f"Error counting batch jobs: {str(e)}")
        return 0

def process_account(account, session):
    """
    Process a single account and return its batch job count
    """
    try:
        print(f"Starting count for account: {account['Id']}")
        
        if account['Id'] == "662627786878":
            client = session.client('batch')
        else:
            accnt = Account(account_id=account['Id'], 
                          sessionName='ResourceQuery', 
                          session=session, 
                          region='us-west-2')
            accnt.batch = accnt.client_config('batch')
            client = accnt.batch
            
        account_job_count = count_batch_jobs(client)
        print(f"Batch job count for account {account['Id']}: {account_job_count}")
        return account_job_count
        
    except Exception as e:
        print(f"Error processing account {account['Id']}: {str(e)}")
        return 0

def main():
    session = boto3.Session(profile_name="ct_master", region_name='us-west-2')
    account_list = get_org_account_list(session)
    total_jobs = 0
    
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
                job_count = future.result()
                total_jobs += job_count
            except Exception as e:
                print(f"Account {account['Id']} generated an exception: {str(e)}")
    
    print(f"Total batch jobs across all accounts: {total_jobs}")

if __name__ == "__main__":
    main()
