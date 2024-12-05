import sys
import os
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)

from aws_cloudformation.CFTDeploy_v1_0_0 import assume_role, get_sts_client
from botocore.exceptions import ClientError
from unittest.mock import patch, MagicMock
import boto3
import pytest

class TestCftdeployV100:
    
    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_empty_session_name(self, mock_get_sts):
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        
        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            assume_role('123456789012', '')
        
        # Verify assume_role was never called due to validation error
        mock_sts.assume_role.assert_not_called()
        assert 'RoleSessionName must be provided' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_incorrect_type(self, mock_get_sts):
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts

        # Act & Assert
        with pytest.raises(TypeError) as exc_info:
            assume_role(123, 'test_session')

        # Verify assume_role was never called due to validation error
        mock_sts.assume_role.assert_not_called()
        assert 'Account ID must be a string' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_invalid_account_id(self, mock_get_sts):
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts

        # Test assume_role with an invalid Account ID
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid account ID'}},
            'AssumeRole'
        )
        
        with pytest.raises(ClientError) as exc_info:
            assume_role('123456789012', 'test_session')
        
        assert 'Invalid account ID' in str(exc_info.value)

    # @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    # def test_assume_role_invalid_duration(self, mock_get_sts):
    #     """
    #     Test assume_role with an invalid duration
    #     """
    #     # Setup the mock STS client
    #     mock_sts = MagicMock()
    #     mock_get_sts.return_value = mock_sts

    #     # Act & Assert
    #     with pytest.raises(ValueError) as exc_info:
    #         assume_role('123456789012', 'test_session', duration=400)
        
    #     # Verify assume_role was never called due to validation error
    #     mock_sts.assume_role.assert_not_called()
    #     assert 'DurationSeconds must be between 900 and 43200' in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_invalid_duration(self, mock_get_sts):
        """
        Test assume_role with an invalid duration
        """
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        
        # Configure mock to raise the same error AWS would
        mock_sts.assume_role.side_effect = ClientError(
            {
                'Error': {
                    'Code': 'ValidationError',
                    'Message': 'Duration must be a value between 900 and 43200 seconds'
                }
            },
            'AssumeRole'
        )

        # Act & Assert
        with pytest.raises(ClientError) as exc_info:
            assume_role('123456789012', 'test_session', duration=400)
        print(exc_info.value)

        # Verify assume_role was called with the invalid duration
        mock_sts.assume_role.assert_called_once_with(
            RoleArn='arn:aws:iam::123456789012:role/AWSControlTowerExecution',
            RoleSessionName='test_session',
            DurationSeconds=400
        )
        
        # Verify the error message
        assert 'Duration must be a value between 900 and 43200 seconds' in str(exc_info.value)


    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_missing_credentials(self, mock_get_sts):
        """
        Test assume_role when the response is missing Credentials
        """
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        mock_sts.assume_role.return_value = {}
        
        # Act & Assert
        with pytest.raises(KeyError) as exc_info:
            assume_role('123456789012', 'test_session')
        print(exc_info.value)

        # Verify assume_role was called once
        mock_sts.assume_role.assert_called_once_with(
            RoleArn='arn:aws:iam::123456789012:role/AWSControlTowerExecution',
            RoleSessionName='test_session',
            DurationSeconds=900
        )
        
        assert "'Credentials'" in str(exc_info.value)

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_sts_error(self, mock_get_sts):
        """
        Test assume_role when STS throws an unexpected error
        """
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'UnexpectedError', 'Message': 'An unexpected error occurred'}},
            'AssumeRole'
        )
        
        # Act & Assert
        with pytest.raises(ClientError) as exc_info:
            assume_role('123456789012', 'test_session')
        
        # Verify assume_role was called once
        mock_sts.assume_role.assert_called_once_with(
            RoleArn='arn:aws:iam::123456789012:role/AWSControlTowerExecution',
            RoleSessionName='test_session',
            DurationSeconds=900
        )
        assert 'An unexpected error occurred' in str(exc_info.value)


    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_client_error(self, mock_get_sts):
        # Arrange
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid account ID'}},
            'AssumeRole'
        )
        
        # Act & Assert
        with pytest.raises(ClientError) as exc_info:
            assume_role('123412341234', 'test_session')
        
        # Verify assume_role was called once
        mock_sts.assume_role.assert_called_once()

    @patch('aws_cloudformation.CFTDeploy_v1_0_0.get_sts_client')
    def test_assume_role_success(self, mock_get_sts):
        # Arrange
        account_id = '123456789012'
        session_name = 'TestSession'
        duration = 900
        
        # Create mock response
        mock_response = {
            'Credentials': {
                'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                'SessionToken': 'AQoDYXdzEPT//////////wEXAMPLE'
            }
        }
        
        # Setup the mock STS client
        mock_sts = MagicMock()
        mock_get_sts.return_value = mock_sts
        mock_sts.assume_role.return_value = mock_response

        # Act
        result = assume_role(account_id, session_name, duration)

        # Assert
        mock_sts.assume_role.assert_called_once_with(
            RoleArn=f'arn:aws:iam::{account_id}:role/AWSControlTowerExecution',
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
        assert result == mock_response['Credentials']

