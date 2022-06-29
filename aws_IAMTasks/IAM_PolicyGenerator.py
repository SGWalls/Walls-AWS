import boto3
# import aws_cdk.aws_iam as iam
from aws_cdk.aws_iam import PolicyStatement, Effect as eff, PolicyDocument
import os
import time
import json
import logging
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import SSOTokenLoadError
from botocore.exceptions import UnauthorizedSSOTokenError
from IAM_Policies import Policies


def add_access(Sid=None,Effect=eff.DENY,Action=None,Resource=None,
               Principal=None,Condition=None, *args, **kwargs):
    if Effect == "Allow":
        Effect = eff.ALLOW
    elif Effect == "Deny":
        Effect = eff.DENY
    params = {}
    arg_dict = {
        "sid": Sid,
        "effect": Effect,
        "actions": Action,
        "resources": Resource,
        "principals": Principal,
        "conditions": Condition,
        "not_actions": kwargs['NotAction'] if kwargs.get('NotAction') 
            else None,
        "not_resources": kwargs['NotResource'] if kwargs.get('NotResource') 
            else None,
        "not_principals": kwargs['NotPrincipal'] if kwargs.get('NotPrincipal') 
            else None
    }  
    params.update(arg_dict)
    for k,v in arg_dict.items():
        if not v:
            del(params[k])
        elif (v and not isinstance(v, list)) and (k in ['actions','resources',
                'principals','not_actions','not_resources','not_principals']):
            params[k] = [v]
    return PolicyStatement(**params)
    # return PolicyStatement(
    #     sid=Sid,
    #     effect=Effect,
    #     actions=Action if isinstance(Action,list) else [Action],
    #     resources=Resource if isinstance(Resource,list) else [Resource],
    #     principals=Principal,
    #     conditions=Condition,
    #     **arg_dict
    # )

access_input = input("Name of the Access Policies to use: ")
access_list = access_input.split(',')
iam_policy=PolicyDocument()
userprofile = os.environ["USERPROFILE"]
import_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\AWS_IAM\\IAM_PolicyStatements\\"
)
for file in access_list:
    statement_doc = getattr(Policies, file)
#     statement_filename = file
# # statement_filename = "IAM_testpol.json"
#     statement_import = os.path.join(import_path, statement_filename)
#     with open(statement_import) as json_file:
#         statement_doc = json.load(json_file)
    if isinstance(statement_doc,list):
        for statement in statement_doc: 
            # if statement['Effect'].upper() == 'ALLOW':
            #     statement['Effect'] = eff.ALLOW
            # else:
            #     statement['Effect'] = eff.DENY
            # iam_policy.add_statements(PolicyStatement(
            #     sid=statement['Sid'],
            #     principals=None,
            #     effect=effect,
            #     actions=statement['Action'] if isinstance(statement['Action'],list) 
            #             else [statement['Action']],
            #     resources=statement['Resource'] if isinstance(statement['Resource'],list) else [statement['Resource']],
            #     conditions=statement['Condition'] if statement.get('Condition') else None
            # ))
            iam_policy.add_statements(add_access(**statement))
    else:
        iam_policy.add_statements(add_access(**statement_doc))

print(iam_policy.to_json())