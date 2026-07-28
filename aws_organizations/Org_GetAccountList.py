import boto3
import csv
from datetime import datetime


def get_all_accounts():
    """Retrieve all accounts from AWS Organizations"""
    org_client = boto3.client('organizations')
    accounts = []
    
    # Handle pagination
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    
    return accounts

def write_accounts_to_csv(accounts):
    """Write account information to CSV file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports'
    filename = f'aws_account_list{timestamp}.csv'
    filename = f'{file_path}\\{filename}'
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['Account ID', 'Account Name', 'Email', 'Status'])
        
        # Write account data
        for account in accounts:
            writer.writerow([
                account['Id'],
                account['Name'],
                account['Email'],
                account['Status']
            ])
    
    return filename

def main():
    try:
        # Get all accounts
        accounts = get_all_accounts()
        
        # Write to CSV
        output_file = write_accounts_to_csv(accounts)
        print(f"Successfully wrote account information to {output_file}")
        print(f"Total accounts processed: {len(accounts)}")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
