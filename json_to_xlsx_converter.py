import json
import pandas as pd

# Your JSON data
json_data = [
  {
    "WorkspaceName": "WSAMZN-42F9DNQ7",
    "DirectoryId": "d-92670e78f5",
    "UserName": "KZHAO",
    "IpAddress": "10.178.1.10",
    "State": "STOPPED",
    "WorkspaceId": "ws-b2wxgtk6b",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "POWER",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-5NSE1AS4",
    "DirectoryId": "d-9267704e65",
    "UserName": "HHDEVATA",
    "IpAddress": "10.178.11.239",
    "State": "STOPPED",
    "WorkspaceId": "ws-f3d5jjzq5",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "POWER",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-6ICUC3BM",
    "DirectoryId": "d-9267704e31",
    "UserName": "DMARTINEZ",
    "IpAddress": "10.178.10.53",
    "State": "AVAILABLE",
    "WorkspaceId": "ws-1b1k07t7m",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "PERFORMANCE",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-7048V54R",
    "DirectoryId": "d-9267704e65",
    "UserName": "NVIPIN",
    "IpAddress": "10.178.11.232",
    "State": "AVAILABLE",
    "WorkspaceId": "ws-4k9r2bkl8",
    "WorkspaceProperties": {
      "RunningMode": "ALWAYS_ON",
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "POWER",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-142TNT9R",
    "DirectoryId": "d-9267704e31",
    "UserName": "MALI",
    "IpAddress": "10.178.10.55",
    "State": "STOPPED",
    "WorkspaceId": "ws-j1hg7njgh",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "PERFORMANCE",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-9T491HEQ",
    "DirectoryId": "d-92670e78f5",
    "UserName": "MBDUGGINS",
    "IpAddress": "10.178.1.37",
    "State": "STOPPED",
    "WorkspaceId": "ws-4vw4nygw7",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "POWER",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  },
  {
    "WorkspaceName": "WSAMZN-CAVNFBH8",
    "DirectoryId": "d-92670e78f5",
    "UserName": "GWCARTER",
    "IpAddress": "10.178.9.12",
    "State": "STOPPED",
    "WorkspaceId": "ws-kf6l3ggz4",
    "WorkspaceProperties": {
      "RunningMode": "AUTO_STOP",
      "RunningModeAutoStopTimeoutInMinutes": 480,
      "RootVolumeSizeGib": 175,
      "UserVolumeSizeGib": 100,
      "ComputeTypeName": "PERFORMANCE",
      "Protocols": [
        "PCOIP"
      ],
      "OperatingSystemName": "WINDOWS_SERVER_2016",
      "GlobalAccelerator": {
        "Mode": "INHERITED",
        "PreferredProtocol": "INHERITED"
      }
    }
  }
]

# Flatten the data
flattened_data = []
for item in json_data:
    row = {
        'WorkspaceName': item['WorkspaceName'],
        'DirectoryId': item['DirectoryId'],
        'UserName': item['UserName'],
        'IpAddress': item['IpAddress'],
        'State': item['State'],
        'WorkspaceId': item['WorkspaceId'],
        'RunningMode': item['WorkspaceProperties']['RunningMode'],
        'RunningModeAutoStopTimeoutInMinutes': item['WorkspaceProperties'].get('RunningModeAutoStopTimeoutInMinutes', ''),
        'RootVolumeSizeGib': item['WorkspaceProperties']['RootVolumeSizeGib'],
        'UserVolumeSizeGib': item['WorkspaceProperties']['UserVolumeSizeGib'],
        'ComputeTypeName': item['WorkspaceProperties']['ComputeTypeName'],
        'Protocols': ', '.join(item['WorkspaceProperties']['Protocols']),
        'OperatingSystemName': item['WorkspaceProperties']['OperatingSystemName'],
        'GlobalAcceleratorMode': item['WorkspaceProperties']['GlobalAccelerator']['Mode'],
        'GlobalAcceleratorPreferredProtocol': item['WorkspaceProperties']['GlobalAccelerator']['PreferredProtocol']
    }
    flattened_data.append(row)

# Create DataFrame and export to XLSX
df = pd.DataFrame(flattened_data)
df.to_excel('workspaces_data.xlsx', index=False)
print("XLSX file 'workspaces_data.xlsx' created successfully!")