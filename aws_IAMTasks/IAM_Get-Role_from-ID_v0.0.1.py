import boto3


# Returns the details for the IAM Role with the provided ID
# todo:
#    error logging
def get_session(profileName):
    return boto3.Session(profile_name=profileName,region_name='us-west-2')

profile_name = input("Enter Profile name: ")
target_role_id = input("Enter Role ID: ")
session = get_session(profile_name)
iam = session.client('iam')

roles = iam.list_roles()
role_list = roles['Roles']
while 'Marker' in roles:
    roles = iam.list_roles(Marker=roles['Marker'])
    role_list.extend(roles['Roles'])

target_role = [role for role in role_list if role['RoleId'] == target_role_id ]

print(target_role)

