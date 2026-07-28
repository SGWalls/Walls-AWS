import boto3
import json

session = boto3.Session(profile_name='ops_tools',region_name='us-west-2')
# Initialize IAM client
iam = session.client('iam')
backup_action_list = [
    'backup:AssociateBackupVaultMpaApprovalTeam',
    'backup:CancelLegalHold',
    'backup:CopyFromBackupVault',
    'backup:CopyIntoBackupVault',
    'backup:CreateBackupAccessPoint',
    'backup:CreateBackupPlan',
    'backup:CreateBackupSelection',
    'backup:CreateBackupVault',
    'backup:CreateFramework',
    'backup:CreateLegalHold',
    'backup:CreateLogicallyAirGappedBackupVault',
    'backup:CreateReportPlan',
    'backup:CreateRestoreAccessBackupVault',
    'backup:CreateRestoreTestingPlan',
    'backup:CreateRestoreTestingSelection',
    'backup:CreateTieringConfiguration',
    'backup:DeleteBackupAccessPoint',
    'backup:DeleteBackupPlan',
    'backup:DeleteBackupSelection',
    'backup:DeleteBackupVault',
    'backup:DeleteBackupVaultAccessPolicy',
    'backup:DeleteBackupVaultLockConfiguration',
    'backup:DeleteBackupVaultNotifications',
    'backup:DeleteBackupVaultSharingPolicy',
    'backup:DeleteFramework',
    'backup:DeleteRecoveryPoint',
    'backup:DeleteReportPlan',
    'backup:DeleteRestoreTestingPlan',
    'backup:DeleteRestoreTestingSelection',
    'backup:DeleteTieringConfiguration',
    'backup:DisassociateBackupVaultMpaApprovalTeam',
    'backup:DisassociateRecoveryPoint',
    'backup:DisassociateRecoveryPointFromParent',
    'backup:ListIndexedRecoveryPointsForSearch',
    'backup:PutBackupVaultAccessPolicy',
    'backup:PutBackupVaultLockConfiguration',
    'backup:PutBackupVaultNotifications',
    'backup:PutBackupVaultSharingPolicy',
    'backup:PutRestoreValidationResult',
    'backup:RevokeRestoreAccessBackupVault',
    'backup:SearchRecoveryPoint',
    'backup:StartBackupJob',
    'backup:StartCopyJob',
    'backup:StartReportJob',
    'backup:StartRestoreJob',
    'backup:StartScanJob',
    'backup:StopBackupJob',
    'backup:TagResource',
    'backup:UntagResource',
    'backup:UpdateBackupPlan',
    'backup:UpdateFramework',
    'backup:UpdateGlobalSettings',
    'backup:UpdateRecoveryPointIndexSettings',
    'backup:UpdateRecoveryPointLifecycle',
    'backup:UpdateRegionSettings',
    'backup:UpdateReportPlan',
    'backup:UpdateRestoreTestingPlan',
    'backup:UpdateRestoreTestingSelection',
    'backup:UpdateTieringConfiguration'
]

def scan_backup_policies():
    # Use paginator to handle accounts with many policies
    paginator = iam.get_paginator('list_policies')
    # Scope='Local' filters for customer managed policies only
    # Set OnlyAttached=True to skip unused policies
    for page in paginator.paginate(Scope='All', OnlyAttached=True):
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            
            # 1. Get the default version of the policy to read the document
            policy_info = iam.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_info['Policy']['DefaultVersionId']
            
            policy_version = iam.get_policy_version(
                PolicyArn=policy_arn, 
                VersionId=default_version_id
            )
            
            # 2. Convert policy document to string to scan for 'backup:'
            doc = json.dumps(policy_version['PolicyVersion']['Document'])
            
            if any(action in doc for action in backup_action_list):
                print(f"\nPolicy Found: {policy['PolicyName']}")
                print(f"ARN: {policy_arn}")
                
                # 3. List roles attached to this specific policy
                entities = iam.list_entities_for_policy(
                    PolicyArn=policy_arn,
                    EntityFilter='Role'
                )
                
                roles = [role['RoleName'] for role in entities.get('PolicyRoles', [])]
                if roles:
                    print(f"Attached Roles: {', '.join(roles)}")
                else:
                    print("Attached Roles: None (Check users or groups if needed)")

if __name__ == "__main__":
    scan_backup_policies()
