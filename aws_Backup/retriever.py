import os
import sys
script_dir = os.path.dirname(__file__)
module_dir = os.path.join(script_dir, '..')
sys.path.append(module_dir)
from helpers.helper import validate_sso_token, get_org_account_list, create_logger
from helpers.Account import Account

if __name__ == "__main__":
    pass