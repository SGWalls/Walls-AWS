import boto3


def format_workspace_data(workspace_data):
    return {
        workspace_data['ComputerName']: {
            'DirectoryId': workspace_data['DirectoryId'],
            'UserName': workspace_data['UserName'],
            'IpAddress': workspace_data['IpAddress'],
            'State': workspace_data['State'],
            'WorkspaceId': workspace_data['WorkspaceId'],
            'WorkspaceProperties': workspace_data['WorkspaceProperties']
        }
    }


workspace_search_list = ["WSAMZN-42F9DNQ7",
"WSAMZN-5NSE1AS4",
"WSAMZN-6ICUC3BM",
"WSAMZN-7048V54R",
"WSAMZN-142TNT9R",
"WSAMZN-9T491HEQ",
"WSAMZN-CAVNFBH8"
]
session = boto3.Session(profile_name='user_svcs',region_name='us-west-2')
workspaces = session.client('workspaces')

directoryId_list = [directory['DirectoryId'] for directory in workspaces.describe_workspace_directories()['Directories']]

workspace_dict = {}
for directory in directoryId_list:
    workspace_list_response = workspaces.describe_workspaces(DirectoryId=directory)
    workspace_dict[directory] = []
    for workspace in workspace_list_response['Workspaces']:
        workspace_dict[directory].append(format_workspace_data(workspace))
    while 'NextToken' in workspace_list_response:
        workspace_list_response = workspaces.describe_workspaces( DirectoryId=directory, NextToken=workspace_list_response['NextToken'] )
        for workspace in workspace_list_response['Workspaces']:
            workspace_dict[directory].append(format_workspace_data(workspace))

for workspaceName in workspace_search_list:
    for directory in workspace_dict:
        for workspace in workspace_dict[directory]:
            if workspaceName in workspace:
                print(f"'{workspaceName}': {workspace}")