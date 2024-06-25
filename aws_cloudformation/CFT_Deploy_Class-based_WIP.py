
import boto3


ASSUMED_ROLE = "AWSControlTowerExecution" 


class CloudFormation():
    def __init__(
            self, account_id, logger, role_name=ASSUMED_ROLE, region="us-west-2"):
        self.logger = logger
        self.accountid = account_id        
        self.rolename = role_name
        self.mstr_session = boto3.session.Session(profile_name="master",
                                                   region_name=region)
        self.credentials = self.assume_role(self.mstr_session,self.accountid,
                                            "AccountMigrationTasks")
        self.session = boto3.session.Session(
            aws_access_key_id = self.credentials['AccessKeyId'],
            aws_secret_access_key = self.credentials['SecretAccessKey'],
            aws_session_token = self.credentials['SessionToken'],
            region_name=region
            )
        
    def assume_role(self,lcl_session,account_id,session_name,duration=900):
        response = lcl_session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.rolename}",
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        return response['Credentials']

    def client_config(self,creds,service,region='us-west-2'):
        response = boto3.session.Session().client(
            aws_access_key_id = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token = creds['SessionToken'],
            region_name = region,
            service_name = service
        )
        return response
    
    def wait_for_stack_update(self,cloudformation, stack_name):
        """
        Waits for the CloudFormation stack update to complete.

        Args:
            cloudformation (boto3.client): The CloudFormation client.
            stack_name (str): The name of the CloudFormation stack.

        Returns:
            None
        """
        print("Waiting for stack update to complete...")
        waiter = cloudformation.get_waiter("stack_update_complete")
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={
                "Delay": 5,
                "MaxAttempts": 60
            }
        )
        print(f"Stack '{stack_name}' updated successfully.")

    def deploy_cloudformation_stack(self,stack_name):
        """
        Deploys a CloudFormation stack using the provided stack name.

        Args:
            stack_name (str): The name of the CloudFormation stack to be deployed.

        Returns:
            None
        """
        # Generate a unique change set name
        change_set_name = f"{stack_name[:9]}{uuid.uuid4().hex}"

        # Create the change set
        print("Creating change set...")
        cloudformation.create_change_set(
            StackName=stack_name,
            TemplateBody=template,
            ChangeSetName=change_set_name,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )

        # Wait for the change set to be created
        print("Waiting for change set to be created...")
        waiter = cloudformation.get_waiter("change_set_create_complete")
        waiter.wait(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            WaiterConfig={
                "Delay": 5,
                "MaxAttempts": 60,
            },
        )
        print("Change set created.")

        # Execute the change set
        print("Executing change set...")
        cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
        )
        print("Change set executed.")

        # Wait for the stack update to complete
        self.wait_for_stack_update(cloudformation, stack_name)
