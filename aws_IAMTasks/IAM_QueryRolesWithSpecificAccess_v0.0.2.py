import boto3
import json

# --- Configuration ---
PROFILE_NAME = 'ops_tools'
REGION = 'us-west-2'

TARGET_ACTIONS = [
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

# ---------------------

session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
iam = session.client('iam')


def get_managed_policy_statements(policy_arn):
    version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)['PolicyVersion']['Document']
    return doc.get('Statement', [])


def get_all_role_statements(role_name):
    """Returns all Allow statements from attached managed + inline policies for a role."""
    statements = []

    paginator = iam.get_paginator('list_attached_role_policies')
    for page in paginator.paginate(RoleName=role_name):
        for policy in page['AttachedPolicies']:
            statements.extend(get_managed_policy_statements(policy['PolicyArn']))

    paginator = iam.get_paginator('list_role_policies')
    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page['PolicyNames']:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            statements.extend(doc.get('Statement', []))

    return statements


def action_matches(action, target):
    """Check if a policy action string matches a target action, supporting wildcards."""
    action = action.lower()
    target = target.lower()
    if action == '*':
        return True
    if action == target:
        return True
    if action.endswith('*'):
        prefix = action[:-1]
        if target.startswith(prefix):
            return True
    service, _, action_name = action.partition(':')
    t_service, _, t_action = target.partition(':')
    if service == t_service and action_name == '*':
        return True
    return False


def statements_grant_action(statements, target_action):
    """Returns True if any Allow statement in the list grants the target action (no explicit Deny check here)."""
    for stmt in statements:
        effect = stmt.get('Effect', '')
        if effect != 'Allow':
            continue
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if any(action_matches(a, target_action) for a in actions):
            return True
    return False


def boundary_permits_action(boundary_arn, target_action):
    """
    Returns True if the permissions boundary allows the action.
    A boundary must explicitly Allow the action; absence of Allow = deny.
    """
    stmts = get_managed_policy_statements(boundary_arn)
    return statements_grant_action(stmts, target_action)


def get_effective_actions(role):
    """
    Returns the subset of TARGET_ACTIONS that are effectively granted to the role.
    Effective = granted in identity policy AND (no boundary OR boundary also allows it).
    """
    role_name = role['RoleName']
    boundary_arn = role.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')

    statements = get_all_role_statements(role_name)

    effective = []
    for action in TARGET_ACTIONS:
        if not statements_grant_action(statements, action):
            continue
        if boundary_arn and not boundary_permits_action(boundary_arn, action):
            continue
        effective.append(action)

    return effective


def find_roles_with_access():
    results = []
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            effective = get_effective_actions(role)
            if effective:
                results.append({
                    'RoleName': role['RoleName'],
                    'RoleArn': role['Arn'],
                    'EffectiveActions': effective,
                    'HasPermissionsBoundary': bool(role.get('PermissionsBoundary'))
                })
    return results


if __name__ == '__main__':
    print(f"Scanning all roles for effective access to target actions...\n")
    matching_roles = find_roles_with_access()

    if not matching_roles:
        print("No roles found with effective access to the specified actions.")
    else:
        print(f"Found {len(matching_roles)} role(s) with effective access:\n")
        for r in matching_roles:
            boundary_note = " [has boundary]" if r['HasPermissionsBoundary'] else ""
            print(f"  Role: {r['RoleName']}{boundary_note}")
            print(f"  ARN:  {r['RoleArn']}")
            print(f"  Effective Actions: {', '.join(r['EffectiveActions'])}")
            print()
