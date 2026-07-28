from aws_cdk.aws_iam import PolicyStatement, Effect as eff, PolicyDocument
import inquirer
import json
import os
from IAM_Policies import Policies

userprofile = os.environ["USERPROFILE"]
import_path = (
    f"{userprofile}\\Documents\\AWS_Projects\\AWS_IAM\\IAM_PolicyStatements\\"
)

def add_access(Sid=None,Effect='Deny',Action=None,Resource=None,
               Principal=None,Condition=None, *args, **kwargs):
    params = {}
    arg_dict = {
        "sid": Sid,
        "effect": eff.ALLOW if Effect == 'Allow' else eff.DENY,
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

def import_file(filename, filedir=import_path):
    statement_import = os.path.join(filedir, filename)
    with open(statement_import) as json_file:
            return json.load(json_file) 

questions = [
    inquirer.Checkbox('policyChoices',
                      message="What are you interested in?",
                      choices=os.listdir(import_path)
                    ),
]
access_list = inquirer.prompt(questions)['policyChoices']
# access_input = input("Name of the Access Policies to use: ")
# access_list = access_input.split(',')
iam_policy=PolicyDocument()
for file in access_list:
    # statement_doc = getattr(Policies, file)
    statement_doc = import_file(file)
    if isinstance(statement_doc,list):
        for statement in statement_doc: 
            iam_policy.add_statements(add_access(**statement))
    else:
        iam_policy.add_statements(add_access(**statement_doc))

print(iam_policy.to_json())