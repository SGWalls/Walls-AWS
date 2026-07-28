import os
import boto3
import json
from botocore.exceptions import ClientError


class VaultUpdate:
    def __init__(self, account_id):
        self.account_id = account_id
        self.sts_client = boto3.client("sts")
        self.region = "us-west-2"
        self.min_retention = 14
        self.max_retention = 730
        self.changeable_days = 3
        self.cross_account_role_name = os.getenv("CROSS_ACCOUNT_ROLE")

    def assume_role_in_account(self, account_id, cross_account_role_name, session_name="VaultLockAccountSession"):
        role_arn = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BackupVaultLockAccess",
                    "Effect": "Allow",
                    "Action": [
                        "backup:DescribeBackupVault",
                        "backup:PutBackupVaultLockConfiguration",
                        "backup:ListBackupVaults"
                    ],
                    "Resource": "*"
                }
            ]
        }

        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                Policy=json.dumps(policy)
            )
        except ClientError as e:
            print(f"Could not assume role {role_arn}: {e}")
            return None

        creds = response["Credentials"]

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region,
        )

        return {
            "backup": session.client("backup"),
            "ec2": session.client("ec2"),
        }

    def list_all_vaults(self, backup_client):
        vaults = []
        try:
            paginator = backup_client.get_paginator("list_backup_vaults")
            for page in paginator.paginate():
                vaults.extend(page.get("BackupVaultList", []))
            print(f"Found {len(vaults)} vault(s)")
            print (vaults)
            return vaults
        except ClientError as e:
            print(f"Failed to list backup vaults: {e}")
            return None

    def get_vault(self, backup_client, backup_vault_name):
        try:
            response = backup_client.describe_backup_vault(
                BackupVaultName=backup_vault_name
            )
            print(f"Vault found: {backup_vault_name}")
            return response
        except ClientError as e:
            print(f"Backup vault {backup_vault_name} not found or inaccessible: {e}")
            return None

    def update_vault_lock_governance(self, backup_client, backup_vault_name):
        try:
            response = backup_client.put_backup_vault_lock_configuration(
                BackupVaultName=backup_vault_name,
                MinRetentionDays=self.min_retention,
                MaxRetentionDays=self.max_retention
            )
            print(
                f"Updated vault lock for {backup_vault_name} in Governance mode "
                f"with MinRetentionDays={self.min_retention}, "
                f"MaxRetentionDays={self.max_retention}"
            )
            return response
        except ClientError as e:
            print(f"Failed to update vault lock for {backup_vault_name}: {e}")
            return None


def lambda_handler(event, context):
    print("Received event:", event)

    account_id = event.get("account_id", "")
    ou_name = event.get("ou_name", "")
    status = event.get("status", "")

    if not account_id:
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "FAILED",
            "message": "account_id is required",
            "vault_results": []
        }

    if status != "ACTIVE":
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "SKIPPED",
            "message": f"Account skipped because status is {status}",
            "vault_results": []
        }

    vault_updater = VaultUpdate(account_id)

    if not vault_updater.cross_account_role_name:
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "FAILED",
            "message": "CROSS_ACCOUNT_ROLE environment variable is required",
            "vault_results": []
        }

    assumed_clients = vault_updater.assume_role_in_account(
        account_id=account_id,
        cross_account_role_name=vault_updater.cross_account_role_name
    )

    if not assumed_clients:
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "FAILED",
            "message": "Unable to assume cross-account role",
            "vault_results": []
        }

    backup_client = assumed_clients["backup"]

    vault_list = vault_updater.list_all_vaults(backup_client)

    if vault_list is None:
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "FAILED",
            "message": f"Failed to list backup vaults in region {vault_updater.region}",
            "vault_results": []
        }

    if not vault_list:
        return {
            "account_id": account_id,
            "ou_name": ou_name,
            "status": status,
            "processing_status": "SKIPPED",
            "message": f"No backup vaults found in region {vault_updater.region}",
            "vault_results": []
        }

    vault_results = []
    success_count = 0
    skipped_count = 0
    failed_count = 0

    for vault in vault_list:
        vault_name = vault.get("BackupVaultName", "")
        if not vault_name:
            continue

        vault_details = vault_updater.get_vault(
            backup_client=backup_client,
            backup_vault_name=vault_name
        )

        if not vault_details:
            vault_results.append({
                "backup_vault_name": vault_name,
                "processing_status": "FAILED",
                "message": f"Backup vault '{vault_name}' not found in region {vault_updater.region}",
                "region": vault_updater.region,
                "mode": "Governance",
                "min_retention_days": vault_updater.min_retention,
                "max_retention_days": vault_updater.max_retention
            })
            failed_count += 1
            continue

        if vault_details.get("Locked"):
            vault_results.append({
                "backup_vault_name": vault_name,
                "processing_status": "SKIPPED",
                "message": f"Vault lock already present for vault '{vault_name}'",
                "region": vault_updater.region,
                "mode": "Governance",
                "min_retention_days": vault_updater.min_retention,
                "max_retention_days": vault_updater.max_retention
            })
            skipped_count += 1
            continue

        result = vault_updater.update_vault_lock_governance(
            backup_client=backup_client,
            backup_vault_name=vault_name
        )

        if result is not None:
            vault_results.append({
                "backup_vault_name": vault_name,
                "processing_status": "SUCCESS",
                "message": "Vault lock updated successfully",
                "region": vault_updater.region,
                "mode": "Governance",
                "min_retention_days": vault_updater.min_retention,
                "max_retention_days": vault_updater.max_retention
            })
            success_count += 1
        else:
            vault_results.append({
                "backup_vault_name": vault_name,
                "processing_status": "FAILED",
                "message": f"Failed to update vault lock for vault '{vault_name}'",
                "region": vault_updater.region,
                "mode": "Governance",
                "min_retention_days": vault_updater.min_retention,
                "max_retention_days": vault_updater.max_retention
            })
            failed_count += 1

    overall_status = "SUCCESS"
    if failed_count > 0 and success_count == 0 and skipped_count == 0:
        overall_status = "FAILED"
    elif failed_count > 0 or skipped_count > 0:
        overall_status = "PARTIAL_SUCCESS"

    return {
        "account_id": account_id,
        "ou_name": ou_name,
        "status": status,
        "processing_status": overall_status,
        "message": f"Processed {len(vault_results)} vault(s): {success_count} success, {skipped_count} skipped, {failed_count} failed",
        "region": vault_updater.region,
        "mode": "Governance",
        "min_retention_days": vault_updater.min_retention,
        "max_retention_days": vault_updater.max_retention,
        "vault_results": vault_results
    }