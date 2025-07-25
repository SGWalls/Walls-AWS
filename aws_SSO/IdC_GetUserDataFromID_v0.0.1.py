import boto3
from retriever import validate_sso_token

userId_list = [
    "92671d59e0-66adfe32-f63d-46df-bdd0-abb941e35c0d",
    "92671d59e0-bb0adead-d421-40ed-a3cc-824da3d0397d",
    "92671d59e0-275b0c08-98f7-4f6d-8394-4e9f6ab8b7b7",
    "92671d59e0-99e6aaa8-23da-468a-be96-f1627cdc91c1",
    "92671d59e0-1e91146b-f096-4c6e-a946-98c64945d95d",
    "92671d59e0-31d470fa-6689-4cdb-ab0b-dcfba40c2bb8",
    "92671d59e0-10594e3a-6631-4bee-83cc-8292560ed129",
    "92671d59e0-cad9bb26-b61a-4578-8c14-685a276a7555",
    "92671d59e0-42594d5c-887b-4b66-b5fc-d3d15b6280d2"
]

class Assign():
    def __init__(self, session):
        self.session = session
    
    def client_config(self,service,creds=None,region='us-west-2'):
        if creds:
            response = boto3.session.Session().client(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region,
                service_name=service
            )
        else:
            response = self.session.client(
                region_name=region,
                service_name=service
            ) if self.session else boto3.session.Session().client(
                region_name=region,
                service_name=service
            )
        return response

    def get_directory_details(self):
        ds = self.client_config('ds')
        ds_response = ds.describe_directories()['DirectoryDescriptions'][0]
        return ds_response

    def get_user_detail(self,user_id):
        idStore = self.client_config('identitystore')
        response = idStore.describe_user(
            IdentityStoreId=self.get_directory_details()['DirectoryId'],
            UserId=user_id
        )
        return response

if __name__ == "__main__":
    session = boto3.session.Session(profile_name='ct_master',region_name='us-west-2')
    validate_sso_token(session)
    assign = Assign(session)
    for user_id in userId_list:
        user_detail = assign.get_user_detail(user_id)
        print(f"{user_id} : {user_detail['UserName']}")
        




