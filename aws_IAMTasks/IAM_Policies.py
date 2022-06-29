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

class Policies():
    createRole = import_file('IAM_IAM-CreateRole.json')
    passRole = import_file('IAM_IAM-PassRole.json')
    manageInstances = import_file('IAM_EC2-Create&MngInstances.json')
    manageSecGroups = import_file('IAM_EC2-SecurityGroup_Manage.json')

