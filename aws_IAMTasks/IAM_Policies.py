import json
import os


userprofile = os.environ["USERPROFILE"]
import_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\AWS_IAM\\IAM_PolicyStatements\\"
)

def import_file(filename, filedir=import_path):
    statement_import = os.path.join(filedir, filename)
    with open(statement_import) as json_file:
            return json.load(json_file) 


def create_statement(
    actions = None,
    conditions = None,
    effect = None,
    not_actions = None,
    not_principals = None,
    not_resources = None,
    principals = None,
    resources = None,
    sid = None
):
    values = {}
    if actions is not None:
       values["Action"] = actions
    if conditions is not None:
       values["Condition"] = conditions
    if effect is not None:
       values["Effect"] = effect
    if not_actions is not None:
       values["NotAction"] = not_actions
    if not_principals is not None:
       values["NotPrincipal"] = not_principals
    if not_resources is not None:
       values["NotResources"] = not_resources
    if principals is not None:
       values["Principal"] = principals
    if resources is not None:
       values["Resource"] = resources
    if sid is not None:
       values["Sid"] = sid
    return values

class Policies():
    createRole = import_file('IAM_IAM-CreateRole.json')
    passRole = import_file('IAM_IAM-PassRole.json')
    manageInstances = import_file('IAM_EC2-Create&MngInstances.json')
    manageSecGroups = import_file('IAM_EC2-SecurityGroup_Manage.json')
    privateApiGw = import_file('IAM_API-Gateway_Private.json')
    
