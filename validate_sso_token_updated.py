import configparser
import os
import subprocess
import shlex
import botocore.exceptions

def validate_sso_token(session):
    """
    Validates if the AWS SSO token for a given session is still valid.
    Triggers login if token is expired or invalid.
    Args:
        session (str): The session object to validate
    Returns:
        bool: True if valid session established, False otherwise
    """
    try:
        # Try to create a session with the profile
        sts = session.client('sts')
        # Test the credentials by making a simple API call
        sts.get_caller_identity()
        return True
    except (botocore.exceptions.TokenRetrievalError,
            botocore.exceptions.UnauthorizedSSOTokenError) as e:
        logger.info(e)
        
        # Get the profile to use for SSO login
        login_profile = _get_sso_profile(session.profile_name)
        
        logger.info(f"SSO token for profile {login_profile} is expired or invalid. Initiating login...")
        try:
            subprocess.run(shlex.split(f"aws sso login --profile {login_profile}"))
            return True
        except subprocess.CalledProcessError as sso_error:
            logger.info(f"Failed to login with SSO: {sso_error}")
            return False
    except Exception as e:
        logger.info(e)
        return False

def _get_sso_profile(profile_name):
    """
    Gets the appropriate profile for SSO login, checking for source_profile.
    """
    config_path = os.path.expanduser('~/.aws/config')
    config = configparser.ConfigParser()
    config.read(config_path)
    
    section_name = f'profile {profile_name}' if profile_name != 'default' else 'default'
    
    if section_name in config and 'source_profile' in config[section_name]:
        return config[section_name]['source_profile']
    
    return profile_name