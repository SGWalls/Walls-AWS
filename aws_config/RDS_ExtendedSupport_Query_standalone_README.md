# RDS Extended Support Query

Queries an AWS Config multi-account aggregator for all RDS DB Instances and Aurora DB Clusters, then classifies each resource's engine version against the official AWS RDS lifecycle dates to identify anything currently in (or approaching) Extended Support.

Extended Support is an AWS programme that allows you to continue running an RDS engine version after its standard end-of-life date — at an additional per-vCPU-hour charge.  This script helps you find those resources before the bill arrives.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.8+ | `python --version` to check |
| AWS CLI v2 | [Install guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| Named AWS CLI profile | Must have the IAM permissions listed below |
| AWS Config multi-account aggregator | Must already be deployed and collecting data |

Install Python dependencies:

```
pip install boto3 openpyxl
```

---

## Required IAM Permissions

The AWS profile you use must be able to call the following APIs in the region where your Config aggregator lives:

```json
{
  "Effect": "Allow",
  "Action": [
    "config:SelectAggregateResourceConfig",
    "rds:DescribeDBMajorEngineVersions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

> `sts:GetCallerIdentity` is used only to validate that your session credentials are active before the main queries run.

---

## Usage

```
python RDS_ExtendedSupport_Query_standalone.py
```

You will be prompted for three inputs:

| Prompt | Default | Description |
|---|---|---|
| AWS profile name | `default` | The named profile in `~/.aws/config` to use for authentication |
| AWS region | `us-west-2` | The region where your Config aggregator is deployed |
| Config aggregator name | *(required)* | The exact name of your multi-account Config aggregator |

### Finding your Config aggregator name

In the AWS Console: **AWS Config → Aggregators** (ensure you are in the correct region).

Via the CLI:
```
aws configservice describe-configuration-aggregators --query "ConfigurationAggregators[*].ConfigurationAggregatorName"
```

### AWS SSO / IAM Identity Center profiles

If your profile uses AWS SSO, the script will automatically detect an expired token and launch `aws sso login` in your browser.  Once the login completes, re-run the script — it will proceed without prompting again until the token expires.

---

## Output

All output files are written to:

```
~/rds_extended_support_exports/
```

Each run produces two timestamped files:

| File | Description |
|---|---|
| `rds_extended_support_YYYYMMDD_HHMMSS.xlsx` | The main report workbook |
| `rds_extended_support_YYYYMMDD_HHMMSS.log` | Full execution log |

### Excel workbook structure

The workbook contains two sheets:

**Sheet 1 — RDS Instances** (`AWS::RDS::DBInstance`)

| Column | Description |
|---|---|
| Resource Type | Always "DB Instance" |
| Account ID | AWS account number where the resource lives |
| Region | AWS region |
| DB Identifier | The RDS instance identifier |
| ARN | Full resource ARN |
| DNS Name | Instance endpoint hostname |
| Port | Listener port |
| Engine | e.g. `mysql`, `postgres` |
| Engine Version | Full version string, e.g. `8.0.32` |
| DB Instance Class | e.g. `db.r6g.large` |
| Multi-AZ | `true` / `false` |
| Status | e.g. `available` |
| Cluster Identifier | Populated if the instance belongs to an Aurora cluster |
| ES Status | See colour coding below |
| Standard Support End | Date standard support ends (YYYY-MM-DD) |
| Extended Support End | Date extended support ends (YYYY-MM-DD) |
| Owner Tag | Value of the `Owner` resource tag, if present |

**Sheet 2 — Aurora Clusters** (`AWS::RDS::DBCluster`)

Same columns as above, with the addition of **Reader Endpoint** and without **Port**.

### ES Status colour coding

| Colour | Status value | Meaning |
|---|---|---|
| *(no highlight)* | Standard Support | Engine version is within its standard support window — no action needed |
| Red | In Extended Support | Standard support has ended; **additional AWS charges are being incurred** |
| Amber | Unknown (vX.Y not in catalogue) | Version could not be matched to the lifecycle catalogue — investigate manually |
| *(no highlight)* | Not ES Eligible | Engine type (e.g. Oracle, SQL Server) is not subject to the open-source Extended Support programme |

---

## How it works

```
[Script]
   │
   ├─ 1. rds:DescribeDBMajorEngineVersions
   │       Builds a local catalogue of every engine major version
   │       and its Standard / Extended Support end dates.
   │
   ├─ 2. config:SelectAggregateResourceConfig  (AWS::RDS::DBInstance)
   │       Returns a snapshot of every RDS instance across all
   │       accounts and regions covered by the aggregator.
   │
   ├─ 3. config:SelectAggregateResourceConfig  (AWS::RDS::DBCluster)
   │       Same, for Aurora clusters.
   │
   └─ 4. Matches each resource's engine/version against the catalogue
         and writes the classified results to an Excel workbook.
```

No cross-account role assumptions are made.  The Config aggregator already holds a copy of every member account's resource data, so a single set of credentials is sufficient.

---

## Troubleshooting

**"Config aggregator name is required" / script exits immediately**
You pressed Enter without typing an aggregator name.  Re-run and provide the name when prompted.

**"Config query failed" error in the log**
Your profile does not have `config:SelectAggregateResourceConfig` permission, or the aggregator name is incorrect.  Verify both and re-run.

**All rows show "Unknown (vX.Y not in catalogue)"**
The `rds:DescribeDBMajorEngineVersions` call may have failed silently (check the log for DEBUG lines), or the region you specified does not support that API.  Try `us-west-2` if you used a different region.

**Zero rows in the output**
The aggregator may not yet have collected data from member accounts (it can take up to 24 hours after initial setup), or the aggregator name / region combination is wrong.

**SSO login browser window does not open**
Ensure the AWS CLI v2 is installed and on your PATH.  Run `aws sso login --profile <your-profile>` manually, then re-run the script.

---

## No external dependencies beyond standard libraries

The script is fully self-contained.  It does not import from any other file in this repository.  The only third-party packages required are `boto3` and `openpyxl`.
