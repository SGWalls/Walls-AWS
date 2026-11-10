import boto3
import botocore
import configparser
import concurrent.futures
import fnmatch
import logging
import os
import subprocess
import shlex
import pandas as pd
from datetime import datetime

''' updates:
        v0.0.2:
        - added target_action list support
        - added fnmatch for wildcard matching
        - improved resource matching logic
        v0.0.3:
        - added resource matching logic
        - added target_resource list support
        - added required deny resource check
        v0.0.4:
        - REQUIRED_DENY_RESOURCE is now dynamically resolved from any IAM policy
          prefixed with "Boundary_" found in the scanned account
        - fixed resource_matches to be one-directional (policy resource covers target),
          eliminating false positives caused by reverse fnmatch overlap
        - tightened ALLOW_RESOURCE to only flag genuinely broad Allow statements
        - deny check now specifically targets iam:CreatePolicy so policies with only a
          partial Deny (e.g. DeletePolicy/CreatePolicyVersion) are correctly flagged
        - deny resource matching normalises account-specific ARNs against Boundary_ pattern
          so both arn:aws:iam::123456789012:policy/Boundary_* and
          arn:aws:iam::*:policy/Boundary_* satisfy the check
'''

# --- Configuration ---
PROFILE_NAME = 'ct_master'
REGION       = 'us-west-2'
ASSUME_ROLE  = 'AWSControlTowerExecution'

BOUNDARY_PREFIX      = 'Boundary_'
TARGET_ACTION        = ['iam:CreatePolicy', 'iam:Create*', 'iam:*']
DENY_TARGET_ACTION   = 'iam:CreatePolicy'
ALLOW_RESOURCE       = ['*', 'arn:aws:iam::*:policy/*', 'arn:aws:iam::*:*']
BOUNDARY_ARN_PATTERN = 'arn:aws:iam::*:policy/Boundary_*'

OUTPUT_DIR = os.path.join(os.environ['USERPROFILE'], 'Documents', 'AWS_Projects', 'Exports', 'IAM_BoundaryPolicyAudit')
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
        RoleSessionName='BoundaryPolicyAudit'
    )['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    ).client('iam')


def get_policy_statements(iam, policy_arn):
    version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)['PolicyVersion']['Document']
    return doc.get('Statement', [])



def action_matches(policy_action, target_actions):
    """Returns True if the policy action covers any of the target actions (one-directional: policy -> target)."""
    policy_action = policy_action.lower()
    if isinstance(target_actions, str):
        target_actions = [target_actions]
    for target in target_actions:
        target = target.lower()
        if policy_action in ('*', target):
            return True
        # policy action wildcard covers the target (e.g. 'iam:*' covers 'iam:createpolicy')
        if fnmatch.fnmatch(target, policy_action):
            return True
    return False


def resource_matches(policy_resource, target_resources):
    """
    Returns True if the policy resource covers any of the target resources.
    One-directional: does the policy_resource (which may contain wildcards) match the target?
    Avoids false positives by NOT checking if the target pattern matches the policy resource.
    """
    policy_resource = policy_resource.lower()
    if isinstance(target_resources, str):
        target_resources = [target_resources]
    for target in target_resources:
        target = target.lower()
        if policy_resource in ('*', target):
            return True
        # policy resource wildcard covers the target
        if fnmatch.fnmatch(target, policy_resource):
            return True
    return False


def has_allow_create_policy_on_broad_resource(statements):
    """Returns True if any Allow statement grants a TARGET_ACTION on a broad ALLOW_RESOURCE."""
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(action_matches(a, TARGET_ACTION) for a in actions) and \
           any(resource_matches(r, ALLOW_RESOURCE) for r in resources):
            return True
    return False


def deny_resource_covers_boundary_pattern(deny_resource, account_id):
    """
    Returns True if a Deny resource entry covers the Boundary_ policy namespace.
    Accepts account-specific ARNs (arn:aws:iam::<account_id>:policy/Boundary_*),
    wildcard ARNs (arn:aws:iam::*:policy/Boundary_*), or broad wildcards (* / all policies).
    """
    r = deny_resource.lower()
    if r == '*':
        return True
    normalised = r.replace(f':{account_id}:', ':*:')
    return (
        fnmatch.fnmatch(normalised, BOUNDARY_ARN_PATTERN.lower()) or
        fnmatch.fnmatch(normalised, 'arn:aws:iam::*:policy/*') or
        fnmatch.fnmatch(normalised, 'arn:aws:iam::*:*')
    )


def has_deny_create_policy_on_boundary(statements, account_id):
    """
    Returns True only if a Deny statement explicitly blocks iam:CreatePolicy
    on resources covering the Boundary_ namespace.
    A partial Deny (e.g. only DeletePolicy/CreatePolicyVersion) does NOT satisfy this.
    """
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get('Effect') != 'Deny':
            continue
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        if not any(action_matches(a, DENY_TARGET_ACTION) for a in actions):
            continue

        if any(deny_resource_covers_boundary_pattern(r, account_id) for r in resources):
            return True

    return False


def scan_account(account, master_session):
    account_id   = account['Id']
    account_name = account['Name']
    logger.info(f"Scanning account: {account_name} ({account_id})")
    results = []

    try:
        iam = get_iam_client_for_account(master_session, account_id)

        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                if not policy['PolicyName'].startswith(BOUNDARY_PREFIX):
                    continue
                policy_arn  = policy['Arn']
                policy_name = policy['PolicyName']
                try:
                    statements    = get_policy_statements(iam, policy_arn)
                    allows_create = has_allow_create_policy_on_broad_resource(statements)
                    has_deny      = has_deny_create_policy_on_boundary(statements, account_id)

                    if allows_create and not has_deny:
                        logger.info(f"  [FLAGGED] {policy_name} in {account_name} ({account_id})")
                        results.append({
                            'AccountId':   account_id,
                            'AccountName': account_name,
                            'PolicyName':  policy_name,
                            'PolicyArn':   policy_arn,
                            'Issue':       f"Allows iam:CreatePolicy on broad resource with no Deny on {BOUNDARY_ARN_PATTERN}"
                        })
                except Exception as policy_err:
                    logger.warning(f"  Skipping policy {policy_name} in {account_id}: {policy_err}")

    except Exception as e:
        logger.error(f"Failed to scan account {account_id} ({account_name}): {e}")

    logger.info(f"  {account_name} ({account_id}): {len(results)} flagged policy/policies")
    return results


def write_excel(data, output_file):
    df = pd.DataFrame(data)
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Boundary Policy Audit', index=False)
        workbook  = writer.book
        worksheet = writer.sheets['Boundary Policy Audit']
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
        f"IAM_BoundaryPolicyAudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

    logger.info("=" * 120)
    logger.info("Starting Boundary Policy Audit")
    logger.info(f"Scanning for '{BOUNDARY_PREFIX}' policies that allow 'iam:CreatePolicy' on '{ALLOW_RESOURCE}' without a Deny on '{BOUNDARY_ARN_PATTERN}'")
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
    logger.info(f"Scan complete. Total flagged policies: {len(all_results)}")

    timestamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"IAM_BoundaryPolicyAudit_{timestamp}.xlsx")

    if all_results:
        write_excel(all_results, output_file)
        logger.info(f"Excel report written: {output_file}")
    else:
        logger.info("No flagged policies found. No Excel file generated.")

    logger.info("=" * 120)


if __name__ == '__main__':
    main()
