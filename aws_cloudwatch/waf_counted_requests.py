"""
waf_counted_requests.py

Gets all active accounts from AWS Organizations, assumes a role in each account
to list WebACLs via wafv2, then queries CloudWatch directly in each member account
for AllowedRequests, BlockedRequests, and CountedRequests per WebACL.

Usage:
    python waf_counted_requests.py [--hours N] [--stat STAT]
    python waf_counted_requests.py --debug-acl ACL_NAME --debug-acl-account ACCOUNT_ID [--debug-acl-region REGION]

Options:
    --hours N               Hours to look back (default: 24)
    --stat STAT             CloudWatch statistic: Sum | Average | Maximum (default: Sum)
    --debug-acl ACL_NAME    Dump raw CW dimensions for a named WebACL and exit
    --debug-acl-account ID  Account ID to use with --debug-acl
    --debug-acl-region R    Region to use with --debug-acl (default: us-west-2)
"""

import argparse
import sys
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ── Config ────────────────────────────────────────────────────────────────────
PROFILE        = "ct_master"
TARGET_REGIONS = ["us-west-2", "us-east-1"]
CA_BUNDLE      = r"C:\Program Files\Amazon\AWSCLIV2\nskp_config\netskope-cert-bundle.pem"
METRICS        = ["AllowedRequests", "BlockedRequests", "CountedRequests"]
ROLE_NAME      = "AWSControlTowerExecution"
SKIP_ACCOUNTS  = {"662627786878"}
# ─────────────────────────────────────────────────────────────────────────────


def build_session() -> boto3.Session:
    try:
        return boto3.Session(profile_name=PROFILE)
    except ProfileNotFound:
        print(f"[ERROR] AWS profile '{PROFILE}' not found.", file=sys.stderr)
        sys.exit(1)


def get_org_accounts(session: boto3.Session) -> list[dict]:
    org = session.client("organizations", verify=CA_BUNDLE)
    accounts = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        accounts.extend(a for a in page["Accounts"] if a["Status"] == "ACTIVE")
    return accounts


def assume_role_session(base_session: boto3.Session, account_id: str) -> boto3.Session | None:
    sts = base_session.client("sts", verify=CA_BUNDLE)
    try:
        creds = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
            RoleSessionName="waf_acl_discovery",
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError as e:
        print(f"    [WARN] Cannot assume role in {account_id}: {e.response['Error']['Code']}", flush=True)
        return None


def list_web_acls(member_session: boto3.Session, account_id: str, region: str) -> list[str]:
    acl_names = []
    try:
        scope = "CLOUDFRONT" if region == "us-east-1" else "REGIONAL"
        waf = member_session.client("wafv2", region_name=region, verify=CA_BUNDLE)
        response = waf.list_web_acls(Scope=scope, Limit=100)
        while True:
            acl_names.extend(a["Name"] for a in response.get("WebACLs", []))
            if "NextMarker" not in response:
                break
            response = waf.list_web_acls(Scope=scope, Limit=100, NextMarker=response["NextMarker"])
        # For us-east-1 also grab REGIONAL ACLs (non-CloudFront)
        if region == "us-east-1":
            response = waf.list_web_acls(Scope="REGIONAL", Limit=100)
            while True:
                acl_names.extend(a["Name"] for a in response.get("WebACLs", []))
                if "NextMarker" not in response:
                    break
                response = waf.list_web_acls(Scope="REGIONAL", Limit=100, NextMarker=response["NextMarker"])
    except ClientError as e:
        print(f"    [WARN] wafv2 list_web_acls failed in {account_id}/{region}: {e.response['Error']['Code']}", flush=True)
    return list(set(acl_names))


def debug_acl_dimensions(member_session: boto3.Session, acl_name: str, region: str) -> None:
    """Print all CW dimensions AWS has on record for a given WebACL name."""
    cw = member_session.client("cloudwatch", region_name=region, verify=CA_BUNDLE)
    print(f"\n[DEBUG] Dimensions on record for WebACL '{acl_name}' in {region}:")
    for metric_name in METRICS:
        response = cw.list_metrics(Namespace="AWS/WAFV2", MetricName=metric_name)
        matches = [m for m in response.get("Metrics", [])
                   if any(d["Value"] == acl_name for d in m["Dimensions"])]
        for m in matches:
            dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
            print(f"  {metric_name}: {dims}")
    print()


def get_counts_for_account(
    member_session: boto3.Session, account_id: str, region: str,
    acl_names: list[str],
    start: datetime, end: datetime, stat: str
) -> dict[str, dict[str, float]]:
    """Returns {acl_name -> {metric_name -> total}} for the provided WebACL names."""
    if not acl_names:
        return {}

    cw = member_session.client("cloudwatch", region_name=region, verify=CA_BUNDLE)
    sorted_acls = sorted(set(acl_names))

    queries = []
    id_map: dict[str, tuple[str, str]] = {}

    for acl_idx, acl_name in enumerate(sorted_acls):
        for metric_idx, metric_name in enumerate(METRICS):
            qid = f"m{acl_idx}_{metric_idx}"
            queries.append({
                "Id": qid,
                "MetricStat": {
                    "Metric": {
                        "Namespace":  "AWS/WAFV2",
                        "MetricName": metric_name,
                        "Dimensions": [
                            {"Name": "WebACL",  "Value": acl_name},
                            {"Name": "Region",  "Value": region},
                            {"Name": "Rule",    "Value": "ALL"},
                        ],
                    },
                    "Period": 3600,
                    "Stat":   stat,
                },
                "ReturnData": True,
            })
            id_map[qid] = (acl_name, metric_name)

    totals: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    data_paginator = cw.get_paginator("get_metric_data")
    for chunk_start in range(0, len(queries), 500):
        chunk = queries[chunk_start: chunk_start + 500]
        for page in data_paginator.paginate(MetricDataQueries=chunk, StartTime=start, EndTime=end):
            for r in page.get("MetricDataResults", []):
                val = sum(r.get("Values", []))
                if val > 0:
                    acl_name, metric_name = id_map[r["Id"]]
                    totals[acl_name][metric_name] += val

    return totals


def fetch_all_counts(session: boto3.Session, hours: int, stat: str) -> list[dict]:
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    output     = []

    print("  Fetching account list from AWS Organizations ...", flush=True)
    accounts = get_org_accounts(session)
    print(f"  Found {len(accounts)} active account(s).\n")

    for account in accounts:
        account_id   = account["Id"]
        account_name = account["Name"]

        if account_id in SKIP_ACCOUNTS:
            print(f"  [{account_id}] {account_name} — skipped", flush=True)
            continue

        member_session = assume_role_session(session, account_id)
        if not member_session:
            continue

        for region in TARGET_REGIONS:
            print(f"  [{account_id}] {account_name} | {region} ...", flush=True)
            acl_names = list_web_acls(member_session, account_id, region)
            if not acl_names:
                print(f"    (no WebACLs found)", flush=True)
                continue
            print(f"    Found {len(acl_names)} WebACL(s): {', '.join(acl_names)}", flush=True)
            acl_data = get_counts_for_account(member_session, account_id, region, acl_names, start_time, end_time, stat)
            for acl_name, metrics in acl_data.items():
                output.append({
                    "region":       region,
                    "account_id":   account_id,
                    "account_name": account_name,
                    "web_acl":      acl_name,
                    "allowed":      metrics.get("AllowedRequests", 0.0),
                    "blocked":      metrics.get("BlockedRequests", 0.0),
                    "counted":      metrics.get("CountedRequests", 0.0),
                })

    return output


def export_xlsx(results: list[dict], hours: int, stat: str) -> Path:
    window_seconds = hours * 3600
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(r"C:\Users\sgwalls\Documents\AWS_Projects\Exports\WAF_Request_Counts") / f"waf_transactions_{ts}.xlsx"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "WAF Transactions"

    # ── Styles ────────────────────────────────────────────────────────────────
    hdr_fill    = PatternFill("solid", fgColor="1F4E79")
    acct_fill   = PatternFill("solid", fgColor="2E75B6")
    region_fill = PatternFill("solid", fgColor="D6E4F0")
    total_fill  = PatternFill("solid", fgColor="E2EFDA")
    hdr_font    = Font(bold=True, color="FFFFFF", size=11)
    acct_font   = Font(bold=True, color="FFFFFF", size=10)
    region_font = Font(bold=True, color="1F4E79", size=10)
    total_font  = Font(bold=True, size=10)
    thin        = Side(style="thin", color="BFBFBF")
    border      = Border(left=thin, right=thin, top=thin, bottom=thin)
    center      = Alignment(horizontal="center", vertical="center")
    right       = Alignment(horizontal="right",  vertical="center")

    def style_row(row_cells, fill=None, font=None, align=None):
        for cell in row_cells:
            cell.border = border
            if fill:  cell.fill  = fill
            if font:  cell.font  = font
            if align: cell.alignment = align

    # ── Header ────────────────────────────────────────────────────────────────
    headers = ["Region", "Account ID", "Account Name", "WebACL",
               "Allowed", "Blocked", "Counted", "Total", "Req/sec"]
    ws.append(headers)
    style_row(ws[1], fill=hdr_fill, font=hdr_font, align=center)

    # ── Data ──────────────────────────────────────────────────────────────────
    grouped: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        grouped[r["region"]][r["account_id"]].append(r)

    grand_allowed = grand_blocked = grand_counted = 0.0

    for region in sorted(grouped):
        region_rows = [r for accts in grouped[region].values() for r in accts]
        reg_allowed = sum(r["allowed"] for r in region_rows)
        reg_blocked = sum(r["blocked"] for r in region_rows)
        reg_counted = sum(r["counted"] for r in region_rows)
        reg_total   = reg_allowed + reg_blocked + reg_counted

        for account_id in sorted(grouped[region]):
            rows = grouped[region][account_id]
            for r in sorted(rows, key=lambda x: x["allowed"] + x["blocked"] + x["counted"], reverse=True):
                total = r["allowed"] + r["blocked"] + r["counted"]
                rps   = total / window_seconds
                ws.append([
                    r["region"], r["account_id"], r["account_name"], r["web_acl"],
                    r["allowed"], r["blocked"], r["counted"], total, round(rps, 4),
                ])
                row_cells = ws[ws.max_row]
                for cell in row_cells[4:]:  # numeric cols
                    cell.alignment = right
                    cell.border = border
                for cell in row_cells[:4]:
                    cell.border = border

        # Region subtotal row
        ws.append([
            f"  {region} SUBTOTAL", "", "", "",
            reg_allowed, reg_blocked, reg_counted, reg_total,
            round(reg_total / window_seconds, 4),
        ])
        style_row(ws[ws.max_row], fill=region_fill, font=region_font)
        for cell in ws[ws.max_row][4:]:
            cell.alignment = right

        grand_allowed += reg_allowed
        grand_blocked += reg_blocked
        grand_counted += reg_counted

    # Grand total row
    grand_total = grand_allowed + grand_blocked + grand_counted
    ws.append([
        "GRAND TOTAL", "", "", "",
        grand_allowed, grand_blocked, grand_counted, grand_total,
        round(grand_total / window_seconds, 4),
    ])
    style_row(ws[ws.max_row], fill=total_fill, font=total_font)
    for cell in ws[ws.max_row][4:]:
        cell.alignment = right

    # ── Column widths ─────────────────────────────────────────────────────────
    col_widths = [14, 16, 35, 60, 14, 14, 14, 14, 10]
    for i, width in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = width

    # ── Freeze header ─────────────────────────────────────────────────────────
    ws.freeze_panes = "A2"

    wb.save(out_path)
    return out_path


def print_results(results: list[dict], hours: int, stat: str) -> None:
    if not results:
        print("\nNo data found.")
        return

    window_seconds = hours * 3600
    grouped: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        grouped[r["region"]][r["account_id"]].append(r)

    grand_total = sum(r["allowed"] + r["blocked"] + r["counted"] for r in results)

    print()
    print("=" * 100)
    print(f"  AWS/WAFV2  Total Transactions  ({stat})")
    print(f"  Lookback: last {hours} hour(s)  |  Profile: {PROFILE}  |  Window: {window_seconds:,}s")
    print("=" * 100)
    print(f"  {'WebACL':<50}  {'Allowed':>12}  {'Blocked':>12}  {'Counted':>12}  {'Total':>12}  {'Req/sec':>10}")
    print("-" * 100)

    for region in sorted(grouped):
        region_rows  = [r for accts in grouped[region].values() for r in accts]
        region_total = sum(r["allowed"] + r["blocked"] + r["counted"] for r in region_rows)
        region_rps   = region_total / window_seconds
        print(f"\n  ┌─ Region: {region}   (region total: {region_total:,.0f}  |  {region_rps:.2f} req/sec)")

        for account_id in sorted(grouped[region]):
            rows       = grouped[region][account_id]
            acct_name  = rows[0]["account_name"]
            acct_total = sum(r["allowed"] + r["blocked"] + r["counted"] for r in rows)
            acct_rps   = acct_total / window_seconds
            print(f"  │")
            print(f"  ├── {account_id}  {acct_name:<35}  (total: {acct_total:,.0f}  |  {acct_rps:.2f} req/sec)")

            for r in sorted(rows, key=lambda x: x["allowed"] + x["blocked"] + x["counted"], reverse=True):
                total = r["allowed"] + r["blocked"] + r["counted"]
                rps   = total / window_seconds
                print(
                    f"  │     {r['web_acl']:<50}"
                    f"  {r['allowed']:>12,.0f}"
                    f"  {r['blocked']:>12,.0f}"
                    f"  {r['counted']:>12,.0f}"
                    f"  {total:>12,.0f}"
                    f"  {rps:>10.2f}"
                )

    print()
    print("=" * 100)
    print(
        f"  GRAND TOTAL  |  Transactions: {grand_total:,.0f}"
        f"  |  Rate: {grand_total / window_seconds:.2f} req/sec"
    )
    print("=" * 100)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Query AWS/WAFV2 total transactions across all org accounts."
    )
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--stat", default="Sum", choices=["Sum", "Average", "Maximum", "SampleCount"],
                        help="CloudWatch statistic (default: Sum)")
    parser.add_argument("--debug-acl", metavar="ACL_NAME",
                        help="Dump raw CW dimensions for a named WebACL and exit")
    parser.add_argument("--debug-acl-account", metavar="ACCOUNT_ID",
                        help="Account ID to use with --debug-acl")
    parser.add_argument("--debug-acl-region", metavar="REGION", default="us-west-2",
                        help="Region to use with --debug-acl (default: us-west-2)")
    args = parser.parse_args()

    print(f"\nBuilding session from profile '{PROFILE}' ...")
    session = build_session()

    if args.debug_acl:
        if not args.debug_acl_account:
            print("[ERROR] --debug-acl requires --debug-acl-account", file=sys.stderr)
            sys.exit(1)
        member_session = assume_role_session(session, args.debug_acl_account)
        if member_session:
            debug_acl_dimensions(member_session, args.debug_acl, args.debug_acl_region)
        sys.exit(0)

    print(f"Fetching WAF transactions ({args.stat}, last {args.hours}h) ...")
    print(f"Regions: {', '.join(TARGET_REGIONS)}\n")

    try:
        results = fetch_all_counts(session, args.hours, args.stat)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        print(f"\n[ERROR] {code} – {msg}", file=sys.stderr)
        print(f"Refresh your session:  aws sso login --profile {PROFILE}", file=sys.stderr)
        sys.exit(1)

    print_results(results, args.hours, args.stat)

    out_path = export_xlsx(results, args.hours, args.stat)
    print(f"  Exported: {out_path}")


if __name__ == "__main__":
    main()
