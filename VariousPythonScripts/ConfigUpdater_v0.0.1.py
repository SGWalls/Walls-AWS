import configparser
import os
import shutil
from pathlib import Path

def update_sso_config():
    # Get AWS config file path
    home = str(Path.home())
    config_file = os.path.join(home, '.aws', 'config')
    
    # Create backup of original config
    backup_file = config_file + '.backup'
    shutil.copy2(config_file, backup_file)
    print(f"Created backup at: {backup_file}")

    # Read the config file
    config = configparser.ConfigParser()
    config.read(config_file)

    # Track if any changes were made
    changes_made = False

    # Iterate through all sections (profiles)
    for section in config.sections():
        if 'sso_start_url' in config[section] and 'sso_region' in config[section] and 'sso-session' not in section:
            # Check if this is the specific URL we want to change
            if (config[section]['sso_start_url'] == 'https://globeaws.awsapps.com/start' and 
                config[section]['sso_region'] == 'us-west-2'):
                
                # Remove old SSO settings
                config[section].pop('sso_start_url')
                config[section].pop('sso_region')
                
                # Add new SSO session setting
                config[section]['sso_session'] = 'glb_session'
                
                changes_made = True
                print(f"Updated profile: {section}")

    # If changes were made, write the updated config
    if changes_made:
        try:
            with open(config_file, 'w') as configfile:
                config.write(configfile)
            print("\nSuccessfully updated AWS config file")
            print("Don't forget to run: aws configure sso-session --session-name glb_session")
        except Exception as e:
            print(f"\nError writing config file: {e}")
            print(f"Your original config file is backed up at: {backup_file}")
    else:
        print("\nNo matching profiles found that require updates")
        print(f"Removing backup file: {backup_file}")
        os.remove(backup_file)

if __name__ == "__main__":
    try:
        update_sso_config()
    except Exception as e:
        print(f"An error occurred: {e}")
