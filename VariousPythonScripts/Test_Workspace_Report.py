import boto3
import json
import os
import logging
from datetime import datetime
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError

def delimiter(symbol='='):
    logger.info(symbol * 120)


def test_token(session=boto3):
    client = session.client('sts')
    try:
        client.get_caller_identity()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError) as e:
        if "expired or is otherwise invalid" in str(e):
            delimiter()
            logger.info(e)
            logger.info("Reinitiating SSO Login...")
            os.system(f"aws sso login --profile {session.profile_name}")
    return 

logger = logging.getLogger('Workspaces')
logger.setLevel(logging.INFO)
region = 'us-west-2'

session = boto3.session.Session(profile_name="user_svcs",region_name="us-west-2")
test_token(session)

bad_workspaces = ["WSAMZN-0RUHHCPI","WSAMZN-1594GNT5","WSAMZN-1A7J8FG1",
                "WSAMZN-1H8RA5VP","WSAMZN-2B9PAQET","WSAMZN-2I37KKDU",
                "WSAMZN-361KK3IG","WSAMZN-37UMKBII","WSAMZN-3SE2CQ7I",
                "WSAMZN-3SHDTHVB","WSAMZN-48GBKERI","WSAMZN-5S78BPRR",
                "WSAMZN-65J2S7LT","WSAMZN-6CK3HPA4","WSAMZN-6G9B9V0E",
                "WSAMZN-6NJL4CC6","WSAMZN-7FSBP4CS","WSAMZN-87RVHCQ4",
                "WSAMZN-8JSJ0A2D","WSAMZN-9321BATR","WSAMZN-9AIMF4GH",
                "WSAMZN-9AVDA084","WSAMZN-A7UN0BAR","WSAMZN-CE1ABAHU",
                "WSAMZN-CE322R99","WSAMZN-D5J550CS","WSAMZN-D8CHCTNC",
                "WSAMZN-DHQAST1A","WSAMZN-DKRCBM16","WSAMZN-DTKTC06T",
                "WSAMZN-E27JP0T6","WSAMZN-EAE1SQVH","WSAMZN-EAVIKQJK",
                "WSAMZN-EKNMPG79","WSAMZN-EQSORH8I","WSAMZN-G46A6QTI",
                "WSAMZN-GBODKAR0","WSAMZN-HO3JPL63","WSAMZN-HP111RKT",
                "WSAMZN-HRK59FG4","WSAMZN-IBBRHS2K","WSAMZN-JPHV0QHR",
                "WSAMZN-JSRBVNPO","WSAMZN-KALOICSI","WSAMZN-KD7TSARQ",
                "WSAMZN-KRG04MSS","WSAMZN-LPN13JGA","WSAMZN-M5T24LPA",
                "WSAMZN-MF950PPT","WSAMZN-MHAMFE71","WSAMZN-NL31C3I6",
                "WSAMZN-NQ49CJQ4","WSAMZN-O6VS7U7G","WSAMZN-O8OEMJON",
                "WSAMZN-OB812P9S","WSAMZN-RUT75GKS","WSAMZN-SI14A6SA",
                "WSAMZN-SR1Q4HKM","WSAMZN-T0P3J9GQ","WSAMZN-TS5D34A1",
                "WSAMZN-TU43HV58","WSAMZN-UEFMIMTB","WSAMZN-UHIKED91",
                "WSAMZN-VLH5CJNO","WSAMZN-VM16FPNG"
]

workspaces = session.client('workspaces')
directory_ids = ["d-92670f4379","d-92670e78f5","d-926702c3eb",
                "d-9267704e10","d-9267704e60","d-9267704e65",
                "d-9267704e00","d-9267704e31","d-926770421d"]
# directory_id = "d-92670e78f5"
workspace_list = []
for directory_id in directory_ids:
    paginator = workspaces.get_paginator('describe_workspaces')
    page_iterator = paginator.paginate(DirectoryId=directory_id)
    for page in page_iterator:
        workspace_list.extend(page['Workspaces'])

workspaces_dict = {item['UserName']:item['ComputerName'] for item in workspace_list 
              if item['ComputerName'] not in bad_workspaces}
ws_list = [item for item in workspaces_dict.values()]
print(workspaces_dict)
print(len(workspaces_dict))
print(ws_list)