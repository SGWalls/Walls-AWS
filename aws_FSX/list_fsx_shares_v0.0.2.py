import boto3
import csv
import os
import pandas as pd
from datetime import datetime
from retriever import Account, get_org_account_list, validate_sso_token

userprofile = os.environ["USERPROFILE"]

def get_fsx_shares(fsx_client, account_id):
    """Get all FSX file shares from an account"""
    shares = []
    
    try:
        # Get FSX file systems
        paginator = fsx_client.get_paginator('describe_file_systems')
        for page in paginator.paginate():
            for fs in page['FileSystems']:
                share_info = {
                    'AccountId': account_id,
                    'FileSystemId': fs['FileSystemId'],
                    'FileSystemType': fs['FileSystemType'],
                    'Lifecycle': fs['Lifecycle'],
                    'StorageCapacity': fs.get('StorageCapacity', 'N/A'),
                    'VpcId': fs.get('VpcId', 'N/A'),
                    'SubnetIds': ','.join(fs.get('SubnetIds', [])),
                    'DNSName': fs.get('DNSName', 'N/A'),
                    'WindowsConfiguration': fs.get('WindowsConfiguration', {}).get('SelfManagedActiveDirectoryConfiguration',{}).get('DomainName',{})
                }
                
                # Add Windows-specific info if available
                if 'WindowsConfiguration' in fs:
                    win_config = fs['WindowsConfiguration']
                    share_info['ActiveDirectoryId'] = win_config.get('ActiveDirectoryId', 'N/A')
                    share_info['ThroughputCapacity'] = win_config.get('ThroughputCapacity', 'N/A')
                
                # Add Lustre-specific info if available
                if 'LustreConfiguration' in fs:
                    lustre_config = fs['LustreConfiguration']
                    share_info['MountName'] = lustre_config.get('MountName', 'N/A')
                    share_info['DataRepositoryConfiguration'] = str(lustre_config.get('DataRepositoryConfiguration', 'N/A'))
                
                shares.append(share_info)
                
    except Exception as e:
        print(f"Error getting FSX shares for account {account_id}: {str(e)}")
    
    return shares

def main():
    session = boto3.Session(profile_name="ct_master", region_name='us-west-2')
    validate_sso_token(session)
    # Get all organization accounts
    account_list = get_org_account_list(session)
    all_shares = []
    
    print(f"Searching FSX shares across {len(account_list)} accounts...")
    
    for account in account_list:
        account_id = account['Id']
        print(f"Checking account: {account_id}")
        
        try:
            if account_id == "662627786878":  # Master account
                fsx_client = session.client('fsx')
                shares = get_fsx_shares(fsx_client, account_id)
            else:
                accnt = Account(account_id=account_id, sessionName='FSXQuery', session=session, region='us-west-2')
                fsx_client = accnt.client_config('fsx')
                shares = get_fsx_shares(fsx_client, account_id)
            
            all_shares.extend(shares)
            print(f"Found {len(shares)} FSX shares in account {account_id}")
            
        except Exception as e:
            print(f"Failed to access account {account_id}: {str(e)}")
    
    # Export results to CSV
    if all_shares:
        df = pd.DataFrame(all_shares)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        excelfilename = (f"FSX_FileServerList-{timestamp}.xlsx")
        export_path = (
        f"{userprofile}\\Documents\\AWS_Projects\\Exports\\FSXShare_Data\\")
        if not os.path.exists(export_path):
            os.makedirs(export_path)
        output_file = os.path.join(export_path,excelfilename)
        
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            # Write DataFrame to Excel
            df.to_excel(writer, sheet_name='FSXShares', index=False)
            
            # Get workbook and worksheet objects to apply formatting
            workbook = writer.book
            worksheet = writer.sheets['FSXShares']
            
            # Add some formatting
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#D3D3D3',
                'border': 1
            })
            
            # Format the header row
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Adjust column widths
            for idx, col in enumerate(df.columns):
                max_length = max(
                    df[col].astype(str).apply(len).max(),
                    len(col)
                )
                worksheet.set_column(idx, idx, max_length + 2)

        print(f"Data exported to {output_file}")


        # timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # filename = f"fsx_shares_{timestamp}.csv"
        
        # with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        #     fieldnames = ['AccountId', 'FileSystemId', 'FileSystemType', 'Lifecycle', 
        #                  'StorageCapacity', 'VpcId', 'SubnetIds', 'DNSName', 'CreationTime',
        #                  'ActiveDirectoryId', 'ThroughputCapacity', 'MountName', 'DataRepositoryConfiguration']
        #     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        #     writer.writeheader()
        #     writer.writerows(all_shares)
        
        # print(f"\nTotal FSX shares found: {len(all_shares)}")
        # print(f"Results exported to: {filename}")
    else:
        print("No FSX shares found across all accounts.")

if __name__ == "__main__":
    main()