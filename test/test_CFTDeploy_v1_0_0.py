import sys
import os
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)
from aws_cloudformation.CFTDeploy_v1_0_0 import assume_role, get_sts_client
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from unittest.mock import patch, MagicMock
import boto3
import pytest

class TestCftdeployV100:

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_empty_session_name(self, mock_sts):
        """
        Test assume_role with an empty session name
        """
        with pytest.raises(ValueError) as exc_info:
            assume_role('123456789012', '')
        
        assert 'RoleSessionName must be provided' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_incorrect_type(self, mock_sts):
        """
        Test assume_role with incorrect input types
        """
        with pytest.raises(TypeError):
            assume_role(123456789012, 'test_session')

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_invalid_account_id(self, mock_sts):
        """
        Test assume_role with an invalid account ID
        """
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid account ID'}},
            'AssumeRole'
        )
        
        with pytest.raises(ClientError) as exc_info:
            assume_role('invalid_account', 'test_session')
        
        assert 'Invalid account ID' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_invalid_duration(self, mock_sts):
        """
        Test assume_role with an invalid duration
        """
        with pytest.raises(ValueError) as exc_info:
            assume_role('123456789012', 'test_session', duration=0)
        
        assert 'DurationSeconds must be between 900 and 43200' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_missing_credentials(self, mock_sts):
        """
        Test assume_role when the response is missing Credentials
        """
        mock_sts.assume_role.return_value = {}
        
        with pytest.raises(KeyError) as exc_info:
            assume_role('123456789012', 'test_session')
        
        assert "'Credentials'" in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_sts_error(self, mock_sts):
        """
        Test assume_role when STS throws an unexpected error
        """
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'UnexpectedError', 'Message': 'An unexpected error occurred'}},
            'AssumeRole'
        )
        
        with pytest.raises(ClientError) as exc_info:
            assume_role('123456789012', 'test_session')
        
        assert 'An unexpected error occurred' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_success(self, mock_sts):
        """
        Test that assume_role successfully returns credentials when given valid inputs.
        """
        # Arrange
        account_id = '123456789012'
        session_name = 'TestSession'
        duration = 900
        expected_credentials = {
            'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
            'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'SessionToken': 'AQoDYXdzEPT//////////wEXAMPLE'
        }
        
        mock_sts.assume_role.return_value = {'Credentials': expected_credentials}

        # Act
        result = assume_role(account_id, session_name, duration)

        # Assert
        mock_sts.assume_role.assert_called_once_with(
            RoleArn=f'arn:aws:iam::{account_id}:role/AWSControlTowerExecution',
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        assert result == expected_credentials