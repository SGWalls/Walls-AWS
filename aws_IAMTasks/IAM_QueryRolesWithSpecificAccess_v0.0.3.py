import boto3
import botocore
import configparser
import concurrent.futures
import logging
import os
import subprocess
import shlex
import pandas as pd
from datetime import datetime

# --- Configuration ---
PROFILE_NAME    = 'ct_master'
REGION          = 'us-west-2'
ASSUME_ROLE     = 'AWSControlTowerExecution'

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

OUTPUT_DIR = os.path.join(os.environ['USERPROFILE'], 'Documents', 'AWS_Projects', 'Exports', 'IAM_RoleAccessAudit')
# ---------------------


def create_logger(logger_name, log_path, log_file_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s ::%(levelname)s:: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler = logging.FileHandler(os.path.join(log_path, log_file_name))
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def validate_sso_token(session):
    def _get_sso_profile(profile_name):
        config_path = os.path.expanduser('~/.aws/config')
        config = configparser.ConfigParser()
        config.read(config_path)
        section_name = f'profile {profile_name}' if profile_name != 'default' else 'default'
        if section_name in config and 'source_profile' in config[section_name]:
            return config[section_name]['source_profile']
        return profile_name

    try:
        session.client('sts').get_caller_identity()
        return True
    except (botocore.exceptions.TokenRetrievalError,
            botocore.exceptions.UnauthorizedSSOTokenError) as e:
        logger.info(e)
        login_profile = _get_sso_profile(session.profile_name)
        logger.info(f"SSO token expired for profile '{login_profile}'. Initiating login...")
        try:
            subprocess.run(shlex.split(f"aws sso login --profile {login_profile}"))
            return True
        except subprocess.CalledProcessError as sso_error:
            logger.info(f"Failed to login with SSO: {sso_error}")
            return False
    except Exception as e:
        logger.info(e)
        return False


def get_iam_client_for_account(master_session, account_id):
    creds = master_session.client('sts').assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{ASSUME_ROLE}",
        RoleSessionName='IAMRoleAccessAudit'
    )['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    ).client('iam')


def get_managed_policy_statements(iam, policy_arn):
    version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)['PolicyVersion']['Document']
    return doc.get('Statement', [])


def get_all_role_statements(iam, role_name):
    try:
        statements = []
        paginator = iam.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy in page['AttachedPolicies']:
                statements.extend(get_managed_policy_statements(iam, policy['PolicyArn']))

        paginator = iam.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page['PolicyNames']:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                statements.extend(doc.get('Statement', []))

        return statements
    except Exception as e:
        logger.warning(f"  Exception!!!")
        raise


def action_matches(action, target):
    action, target = action.lower(), target.lower()
    if action in ('*', target):
        # logger.info(f"{action} Matches!")
        return True
    if action.endswith('*') and target.startswith(action[:-1]):
        # logger.info(f"{action} Matches!")
        return True
    service, _, act = action.partition(':')
    t_service, _, _ = target.partition(':')
    return service == t_service and act == '*'


def statements_grant_action(statements, target_action):
    for stmt in statements:
        if isinstance(stmt,dict):
            if stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if any(action_matches(a, target_action) for a in actions):
                return True
    return False


def get_effective_actions(iam, role):
    role_name = role['RoleName']
    boundary_arn = role.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')
    statements = get_all_role_statements(iam, role_name)

    effective = []
    for action in TARGET_ACTIONS:
        if not statements_grant_action(statements, action):
            continue
        if boundary_arn:
            boundary_stmts = get_managed_policy_statements(iam, boundary_arn)
            logger.info(f"    {role_name} has Boundary!!!")
            if not statements_grant_action(boundary_stmts, action):
                continue
        effective.append(action)
    return effective


def scan_account(account, master_session):
    account_id   = account['Id']
    account_name = account['Name']
    logger.info(f"Scanning account: {account_name} ({account_id})")
    results = []

    try:
        iam = get_iam_client_for_account(master_session, account_id)
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                try:
                    role_details = iam.get_role(RoleName=role['RoleName'])
                    effective = get_effective_actions(iam, role_details['Role'])
                    if effective:
                        results.append({
                            'AccountId':             account_id,
                            'AccountName':           account_name,
                            'RoleName':              role['RoleName'],
                            'RoleArn':               role['Arn'],
                            'HasPermissionsBoundary': 'Yes' if role.get('PermissionsBoundary') else 'No',
                            'EffectiveActions':      ', '.join(effective)
                        })
                except Exception as role_err:
                    logger.warning(f"  Skipping role {role['RoleName']} in {account_id}: {role_err}")
    except Exception as e:
        logger.error(f"Failed to scan account {account_id} ({account_name}): {e}")

    logger.info(f"  {account_name} ({account_id}): {len(results)} role(s) found")
    return results


def write_excel(data, output_file):
    df = pd.DataFrame(data)
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Role Access Audit', index=False)
        workbook  = writer.book
        worksheet = writer.sheets['Role Access Audit']
        header_format = workbook.add_format({'bold': True, 'bg_color': '#D3D3D3', 'border': 1})
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
        for idx, col in enumerate(df.columns):
            max_length = max(df[col].astype(str).apply(len).max(), len(col))
            worksheet.set_column(idx, idx, max_length + 2)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log_dir = os.path.join(OUTPUT_DIR, 'logging')
    os.makedirs(log_dir, exist_ok=True)

    global logger
    logger = create_logger(
        __name__,
        log_dir,
        f"IAM_RoleAccessAudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

    logger.info("=" * 120)
    logger.info("Starting IAM Role Access Audit")
    logger.info(f"Target actions count: {len(TARGET_ACTIONS)}")
    logger.info("=" * 120)

    master_session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    validate_sso_token(master_session)

    org = master_session.client('organizations')
    paginator = org.get_paginator('list_accounts')
    accounts = [
        acct for page in paginator.paginate()
        for acct in page['Accounts']
        if acct['Status'] == 'ACTIVE'
    ]
    logger.info(f"Retrieved {len(accounts)} active accounts from Organizations")

    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_account, acct, master_session): acct for acct in accounts}
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    logger.info("=" * 120)
    logger.info(f"Scan complete. Total matching roles found: {len(all_results)}")

    timestamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"IAM_RoleAccessAudit_{timestamp}.xlsx")

    if all_results:
        write_excel(all_results, output_file)
        logger.info(f"Excel report written: {output_file}")
    else:
        logger.info("No matching roles found. No Excel file generated.")

    logger.info("=" * 120)


if __name__ == '__main__':
    main()
