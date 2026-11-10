# AWS IAM Roles Anywhere Setup — Process Document

## Overview
This process configures AWS IAM Roles Anywhere to allow on-premises servers to assume AWS roles using X.509 certificates.

---

## Prerequisites
Before starting, gather the following from the requestor:
- `ONPremServerCertCN` — The on-prem server certificate CN, typically the server's hostname (e.g., `MCKDEVTWEB03.torchmarkcorp.com`)
- `CICDAccountID` — The target CICD AWS account ID

> Using the `CICDAccountID`, look up the account name in the AWS Organizations account list to determine `TargetAccountName`.

---

## Step 1 — Create IAM Role in Globe_Enterprise-RolesAnywhere_Services (317706704995)

**Role Name:** `rolesAnywhere_{AccountName}`
> e.g., `rolesAnywhere_CICD_Conservation`

### Trust Policy
> Replace `{ONPremServerCertCN}` with the value provided by the requestor.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "rolesanywhere.amazonaws.com"
            },
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession",
                "sts:SetSourceIdentity"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/x509Subject/CN": "{ONPremServerCertCN}"
                },
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:rolesanywhere:us-west-2:317706704995:trust-anchor/cbe08b68-3394-455a-813b-c26924501be4"
                }
            }
        }
    ]
}
```

### Permission Policy
> Replace `{CICDAccountID}` with the target account ID.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AssumeRole",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole",
                "sts:SetSourceIdentity"
            ],
            "Resource": [
                "arn:aws:iam::{CICDAccountID}:role/OnPremCodeDeployRole"
            ],
            "Condition": {
                "StringEquals": {
                    "sts:SourceIdentity": [
                        "CN=${aws:PrincipalTag/x509Subject/CN}"
                    ]
                }
            }
        },
        {
            "Sid": "TagSession",
            "Effect": "Allow",
            "Action": [
                "sts:TagSession"
            ],
            "Resource": [
                "arn:aws:iam::{CICDAccountID}:role/OnPremCodeDeployRole"
            ]
        }
    ]
}
```

---

## Step 2 — Create Roles Anywhere Profile

| Field | Value |
|---|---|
| Name | `{TargetAccountName}_RAProfile` (e.g., `CICD_Conservation_RAProfile`) |
| Roles | Role created in Step 1 (e.g., `rolesAnywhere_CICD_Conservation`) |
| All other options | Leave as default |

> Once the profile is created, provide the new profile's ARN to the requestor.

---

## Step 3 — Create IAM Role in Target CICD Account

**Role Name:** `OnPremCodeDeployRole`

### Trust Policy
> Replace `{rolesAnywhere_CICD_AccountName}` with the role name from Step 1, and `{ONPremServerCertCN}` with the cert CN.

> **Note:** The `StringEquals` condition operator is case-sensitive. The `ONPremServerCertCN` value must exactly match the X.509 Subject CN that will be presented by the on-prem server — including casing.
> e.g., `MCKDEVTWEB03.Torchmarkcorp.com` will **not** match `MCKDEVTWEB03.torchmarkcorp.com`

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::317706704995:role/{rolesAnywhere_CICD_AccountName}"
            },
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession"
            ]
        },
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::317706704995:role/{rolesAnywhere_CICD_AccountName}"
            },
            "Action": "sts:SetSourceIdentity",
            "Condition": {
                "StringEquals": {
                    "sts:SourceIdentity": "CN={ONPremServerCertCN}"
                }
            }
        }
    ]
}
```

### Access Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CodeDeployAgent",
            "Effect": "Allow",
            "Action": "codedeploy:*",
            "Resource": "*"
        },
        {
            "Sid": "S3ArtifactAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:ListBucket"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:us-west-2:599499160241:*"
        }
    ]
}
```

---

## Summary of Variables

| Variable | Description | Example |
|---|---|---|
| `ONPremServerCertCN` | On-prem server certificate CN | `MCKDEVTWEB03.torchmarkcorp.com` |
| `CICDAccountID` | Target CICD account ID | `123456789012` |
| `TargetAccountName` | Look up in AWS Organizations using `CICDAccountID` | `CICD_Conservation` |
| `rolesAnywhere_CICD_AccountName` | Role name from Step 1 | `rolesAnywhere_CICD_Conservation` |
