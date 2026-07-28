import boto3
from retriever import validate_sso_token

userId_list = [
   "92671d59e0-0868d570-f055-4e11-902f-bcc8743459d8",
"92671d59e0-1e91146b-f096-4c6e-a946-98c64945d95d",
"92671d59e0-1b9fc8ee-f9c4-4aff-8dd1-bd92f8920d61",
"92671d59e0-5e1cba3d-402c-4984-ae9e-11507eeb0650",
"92671d59e0-66adfe32-f63d-46df-bdd0-abb941e35c0d",
"92671d59e0-f529f6b1-f788-4159-96ef-57c677c6de37",
"92671d59e0-d559f03e-afc7-409d-91bc-c2ebeb3d03a4",
"92671d59e0-4f2b395a-3dad-4bd6-9eac-ec91987a71cd",
"92671d59e0-e01d8e9f-b810-4129-96fd-a8cad0f83551",
"92671d59e0-b24ba951-a621-41ee-8be4-ba610a42f3a9",
"92671d59e0-3daa494a-254a-49bc-96cb-10bdbfb7e6f6",
"92671d59e0-efb888d1-0019-42be-b8f6-a29d71462d27",
"92671d59e0-077ed22f-7d3e-4e8f-b7ba-48527b109ad9",
"92671d59e0-03a18944-3a91-4584-9fbf-5621eb6b4c69",
"92671d59e0-0b9b19ad-d256-4708-8fce-95b1d7754019",
"92671d59e0-c843a5aa-4ad8-4df3-b060-9e6d100ad4d8",
"92671d59e0-608c92fd-e78b-413b-afc0-e4760bcae57e",
"92671d59e0-420f8b7c-81fe-4a21-b969-b25a811bcca7",
"92671d59e0-99e6aaa8-23da-468a-be96-f1627cdc91c1",
"92671d59e0-75a7012b-ffc1-47a9-8e26-98de56bf319d",
"92671d59e0-41af4280-5ae7-4a31-a3af-17dde4b55389",
"92671d59e0-5c00e7e2-dee3-408f-b12d-59204960f6fd",
"92671d59e0-465a3f18-5ea9-4547-9944-c6dc9cf91adf",
"92671d59e0-cded0d2b-e508-4df3-b127-704805d98cc7",
"92671d59e0-42594d5c-887b-4b66-b5fc-d3d15b6280d2",
"92671d59e0-22f61240-1678-4d78-b16f-0188b048b966",
"92671d59e0-1c17727b-ff77-41cb-8427-3b5f9578f323",
"92671d59e0-e1d38529-cf90-4716-9305-d9f463109f3a",
"92671d59e0-f74c5922-18e6-4020-b611-4597cd24df7d",
"92671d59e0-699fedb7-ab35-4b0e-8b97-e877c3d6996f",
"92671d59e0-1debe2d1-17df-4d2f-bf35-928b2ceb0903",
"92671d59e0-abc90fad-04bc-44bf-8ca5-bf32df5b17e5",
"92671d59e0-16d04e1e-8d11-42fb-b7b3-a2e426285dc8",
"92671d59e0-83b2d914-d50f-4ae2-ab40-99ce683292ae",
"92671d59e0-b4f3cd98-2a7a-4909-81eb-ea6b388c6720",
"92671d59e0-5bbb09b5-9429-4024-a362-3a11709ee8da",
"92671d59e0-fb5ba13c-4aff-4f2d-99b0-6a22576a54e7",
"92671d59e0-4289e9ba-e7f5-479b-aaf4-130c3dc5f504",
"92671d59e0-31d470fa-6689-4cdb-ab0b-dcfba40c2bb8",
"92671d59e0-6a7bdfee-34f6-4df4-9891-20f201eaac11",
"92671d59e0-7c305095-a2c1-4d26-a775-0833c56f9fbd",
"92671d59e0-268aab38-7223-49a5-8d94-5bb84eb1c220",
"92671d59e0-bb0adead-d421-40ed-a3cc-824da3d0397d",
"92671d59e0-2bdf43be-39a0-4501-b507-1117a31fa39f",
"92671d59e0-ea758f38-4a31-48e9-a97e-6bc4a0d908ae",
"92671d59e0-c1340345-2385-4637-ae3b-3631f3ab1ab5",
"92671d59e0-10594e3a-6631-4bee-83cc-8292560ed129",
"92671d59e0-d2850e62-7901-44a0-8b22-327e1c4b7b77",
"92671d59e0-38877872-1313-4f8b-904d-b30e18b55489",
"92671d59e0-b3bc2843-48ba-4f01-8492-9f1ebf6a0078",
"92671d59e0-275b0c08-98f7-4f6d-8394-4e9f6ab8b7b7",
"92671d59e0-0510dbb6-8bd8-400f-a13f-a67abbc82b55",
"92671d59e0-41a87104-b885-442e-b23a-57c632618e8d",
"92671d59e0-1efa549d-f0c6-45e3-8f59-5e01836a90cf",
"92671d59e0-f2fd5e94-2bf1-4908-88be-780591475430",
"92671d59e0-ad825f6f-ece0-43bb-b3b7-4d2d9f0db909",
"92671d59e0-479db78c-1f0f-433f-bc70-234d13c7ed7c",
"92671d59e0-984785bf-cc16-479c-8bbe-a05ca3f8bfa9",
"92671d59e0-357e7454-dae1-40c8-a20b-35c02f3419ef",
"92671d59e0-03e2f3b5-f00e-406a-ba68-3c2b392ac94f",
"92671d59e0-7d4e832d-4938-4cf5-add4-0c14301d6fd7",
"92671d59e0-e529500f-f627-4de0-a3b4-54ab91eff2a9",
"92671d59e0-56e70a4c-6fa7-4040-9484-8c60d7a31fe5",
"92671d59e0-0a7c993a-68aa-40c0-95a1-e585b8a71501",
"92671d59e0-50dcecb0-3727-4cd7-93bb-b1467ef08df5",
"92671d59e0-598927f6-2328-4298-9588-13375a2c01cd",
"92671d59e0-ae558b58-d0d1-4271-92bd-e8f2df4049ab",
"92671d59e0-c653c970-f03f-4898-8b7d-0d0388754ac5",
"92671d59e0-099af25a-7e2b-43c7-a632-877b13839a2b",
"92671d59e0-2c01e584-0d26-4d4a-b685-6545cfb265dc",
"92671d59e0-dd94bb92-a8eb-4c68-a43d-44ea7cca2d66",
"92671d59e0-7f20f572-4005-4dd5-aba2-006fbb758873",
"92671d59e0-2875b088-78af-400c-ba4b-d6a451397aa4",
"92671d59e0-5442e04c-408c-4281-a756-17b45b9f8ec5",
"92671d59e0-f8239173-2d9c-4e5f-9fa9-8a035b82280f",
"92671d59e0-569e84ca-7eca-47bb-b353-8b9be9df0585",
"92671d59e0-307a940a-1ae7-49fb-9a4b-897b78b8294f",
"92671d59e0-a38d7711-90f5-4d47-b4fd-b3289d2596ad",
"92671d59e0-547050a2-23c3-41d4-8afd-59b7ab0891c6",
"92671d59e0-d7f87e19-97c4-4fcf-a78b-14cf94d07364",
"92671d59e0-358fcbef-9a67-4eff-8361-d9cf5daf4cb1",
"92671d59e0-8f7acbf5-3c4f-4836-9de8-b9b811646780",
"92671d59e0-c2d8014c-dc1f-4a55-830c-047e6808f671",
"92671d59e0-6c1f539b-9432-4919-9aa3-fad897a3e724",
"92671d59e0-956084e9-bb21-4552-9a30-a87ca5abd71b",
"92671d59e0-53203b56-f6a0-4630-aaf9-c1e1e481b027",
"92671d59e0-a4cc4274-2eed-4d22-a99d-4e3a4e8bdc17",
"92671d59e0-772dea1c-7862-44c7-a89d-5b59f0dc4821",
"92671d59e0-ba5b6f10-8237-463c-a7cf-7e635804b166",
"92671d59e0-8de05a49-b8c0-449e-9ce5-c9b901ea9ac2",
"92671d59e0-c962e6b5-30e7-42a0-9813-bc16b9dca605",
"92671d59e0-96a3face-522b-4daa-91ac-1c035e45f246",
"92671d59e0-e5096463-ac9c-4413-90c0-2a43b688c8dc",
"92671d59e0-7cefa96b-7ec7-4ebc-be1c-b36a2c84fbcf",
"92671d59e0-e22bd272-b396-484c-a787-1761fa7b1f2c",
"92671d59e0-3a878fc1-b771-4a4d-b24f-072622a7d3c9",
"92671d59e0-2e43b8d7-605d-46a0-8e1a-c684ff6ef9a7",
"92671d59e0-04b6165e-1f77-4095-b80f-b220308d6365",
"92671d59e0-c298d707-5b10-46ba-a18e-b5f031f39f95",
"92671d59e0-d52e41aa-36e0-4a3f-a96b-ec8e45bcb319",
"92671d59e0-a7a80f9b-9826-40a5-8c35-69cb36f7a18a",
"92671d59e0-0684783a-ed68-4012-89e3-bcd71e8c138c",
"92671d59e0-8e220ace-c8de-475f-b58d-c96e1cb2d979",
"92671d59e0-2d9dac26-2d13-4c2f-8523-28504c3ba8d2",
"92671d59e0-b07acbd7-ad6f-4e7e-9319-99b1c10f662c",
"92671d59e0-da6db4b9-2c15-4d21-9a19-8baa696f3707",
"92671d59e0-f1f9d4ec-97bb-4bdf-85e5-dca861867d33",
"92671d59e0-7ed6503c-bf79-4b4b-b803-32b40e1e59f0",
"92671d59e0-717c4dd7-f6a6-401e-abfd-1dcf6a2be5cc",
"92671d59e0-31a2a343-416d-410b-806a-e31c8ee60f09",
"92671d59e0-641288be-69db-4208-9fe7-a405f5c3e7bd",
"92671d59e0-48637d63-8a7c-40f1-b2a4-05c39e81918f",
"92671d59e0-20a50bdc-8575-487a-85ef-b11dbbc9394d",
"92671d59e0-b9ca7515-8f76-446d-8102-d6b421c7760a"
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
        # ds_response = ds.describe_directories()['DirectoryDescriptions'][0]
        ds_response = {'DirectoryId':'d-92671d59e0'}
        return ds_response

    def get_user_detail(self,user_id):
        idStore = self.client_config('identitystore')
        response = idStore.describe_user(
            IdentityStoreId=self.get_directory_details()['DirectoryId'],
            UserId=user_id
        )
        return response

if __name__ == "__main__":
    session = boto3.session.Session(profile_name='dev_devops',region_name='us-west-2')
    validate_sso_token(session)
    assign = Assign(session)
    for user_id in userId_list:
        user_detail = assign.get_user_detail(user_id)
        print(f"{user_id} : {user_detail['UserName']}")
        




