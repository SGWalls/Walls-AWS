import boto3


session = boto3.Session(profile_name='user_svcs',region_name='us-west-2')
workspaces = session.client('workspaces')
directoryId = "d-92670e78f5"
computerName = input("What is the computer name? ")
ipAddress = input("What is the IP Address? ")
# powerOn = input("Do you want to power on all workspaces? Y or N ")

paginator = workspaces.get_paginator('describe_workspaces')
page_iterator = paginator.paginate(DirectoryId=directoryId)
for page in page_iterator:
        for workspace in page['Workspaces']:
            # print(f"{workspace['ComputerName']}:{workspace['WorkspaceId']}")
            # if workspace['State'] == 'AVAILABLE':
            #     print(f"{workspace['ComputerName']}:{workspace['WorkspaceId']}")
                # workspaces.start_workspaces(StartWorkspaceRequests=[
                #     {
                #         'WorkspaceId': workspace['WorkspaceId']
                #     }
                # ])
            if ipAddress and workspace['IpAddress'] == ipAddress:
                print(workspace['WorkspaceId'])
            if computerName and workspace['ComputerName'] == computerName:
                print(workspace['WorkspaceId'])