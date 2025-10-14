import boto3
import botocore
import configparser
import logging 
import subprocess, shlex
import os
import csv
from retriever import Account

session = boto3.Session(profile_name='audit_discover',region_name='us-west-2')

logger = logging.getLogger(__name__)
fmmAclName = 'FMManagedWebACL82c0e0e4-1f94-41a4-b6c4-38de2cf4c80c'
def csv_to_dict(filename):
    with open(filename, 'r', encoding='utf-8-sig') as file:
        return list(csv.DictReader(file))

# Load the CSV data
data = csv_to_dict(r"C:\Users\sgwalls\Downloads\AssetDownload_1759417029860.csv")

# print(data)

for acl in data:
    account_id = acl['Account ID'].zfill(12)
    if account_id == '741252614647':
        accnt = Account(account_id, boto3.Session(profile_name='master',region_name='us-west-2'),'acl_discover')
        # waf = boto3.Session(profile_name='master',region_name='us-west-2').client('waf-regional')
        aclName = waf.get_web_acl(WebACLId=acl['ARN'][-36:])['WebACL']['Name']
        if aclName == fmmAclName:
            print(f"{account_id} - {acl['ARN'][-36:]} - {aclName}")
        else:
            print(f"!!!NO MATCH!!!! {account_id} - {acl['ARN'][-36:]} - {aclName}")
    elif account_id == '662627786878':
        waf = boto3.Session(profile_name='ct_master', region_name='us-west-2').client('waf-regional')
        aclName = waf.get_web_acl(WebACLId=acl['ARN'][-36:])['WebACL']['Name']
        if aclName == fmmAclName:
            print(f"{account_id} - {acl['ARN'][-36:]} - {aclName}")
        else:
            print(f"!!!NO MATCH!!!! {account_id} - {acl['ARN'][-36:]} - {aclName}")
    else:
        aclId = acl['ARN'][-36:]
        accnt = Account(account_id, session, 'acl_discover', 'ent-cloudops_resource-discovery')
        accnt.waf = accnt.client_config('waf-regional')
        aclName = accnt.waf.get_web_acl(WebACLId=aclId)['WebACL']['Name']
        if aclName == fmmAclName:
            print(f"{account_id} - {acl['ARN'][-36:]} - {aclName}")
        else:
            print(f"!!!NO MATCH!!!! {account_id} - {acl['ARN'][-36:]} - {aclName}")
