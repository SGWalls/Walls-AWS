import boto3
import json
import os


def get_policy_document(client,PolicyArn):
    iam = client
    policy_document = iam.get_policy_version(
        PolicyArn = PolicyArn,
        VersionId = iam.get_policy(PolicyArn=PolicyArn)['Policy']['DefaultVersionId']
    )['PolicyVersion']['Document']
    return policy_document


environment_mappings = {
    'dev': {
        'AccountId' : '896172592430',
        'ProfileName' : 'cdm_dev',
        'SourceRoleName' : 'FromMaster_CDM_Dev_DataLake_Development'
    },
    'test': {
        'AccountId' : '856695471500',
        'ProfileName' : 'cdm_test',
        'SourceRoleName' : 'FromMaster_CDM_Test_2_Developer'
    },
    'prod':{
        'AccountId' : '838001389413',
        'ProfileName' : 'cdm_prod',
        'SourceRoleName' : 'FromMaster_CDM_Prod_Datalake_Support'
    }
}
role_configs = {}
for env in environment_mappings:
    session = boto3.Session(
        profile_name=environment_mappings[env]['ProfileName'],
        region_name='us-west-2'
    )
    SourceRole = environment_mappings[env]['SourceRoleName']
    iam = session.client('iam')
    # role_configs[env]= { SourceRole : { 'ManagedPolicies': [ role['PolicyArn'] for role in iam.list_attached_role_policies(RoleName=SourceRole)['AttachedPolicies']]}} 
    # role_configs[env]= { SourceRole : { 
    #     'ManagedPolicies':  {policy_arn: iam.get_policy_version(
    #         PolicyArn=policy_arn,
    #         VersionId=iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    #         )['PolicyVersion']['Document'] for 
    #         policy_arn in [ role['PolicyArn'] for role in 
    #         iam.list_attached_role_policies(
    #             RoleName=SourceRole)['AttachedPolicies']
    #         ]
    #         }
    #     }
    # }
    role_configs[env]= { SourceRole : { 
        'ManagedPolicies':  {policy_arn: get_policy_document(iam,policy_arn) for 
            policy_arn in [ role['PolicyArn'] for role in 
            iam.list_attached_role_policies(
                RoleName=SourceRole)['AttachedPolicies']
            ]
            }
        }
    }
    role_configs[env][SourceRole]['InlinePolicies'] = [policy for policy in iam.list_role_policies(RoleName=SourceRole)['PolicyNames']]
    role_configs[env][SourceRole]['InlinePolicies'] = { 
        policy_name: iam.get_role_policy(
            RoleName=SourceRole,
            PolicyName=policy_name
        )['PolicyDocument'] for policy_name in [ policy for policy in
            iam.list_role_policies(RoleName=SourceRole)['PolicyNames']
        ]
    }


