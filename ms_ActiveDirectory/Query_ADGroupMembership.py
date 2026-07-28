import getpass
import os
import re
import sys
from ldap3 import Server, Connection, ALL, NTLM

AD_SEARCH_BASE = 'DC=tmk,DC=ent,DC=lc'

def get_secure_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

def authenticate_user(username, password):
    AD_SERVER = os.environ.get('AD_SERVER', 'mktmp1dc01.tmk.ent.lc')
    
    try:
        server = Server(AD_SERVER, get_info=ALL)
        conn = Connection(server, user=username, password=password, authentication=NTLM)
        if conn.bind():
            print("Authentication successful!")
            return conn
        else:
            print("Authentication failed.")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def get_user_groups(username, conn):
    user_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
    conn.search(AD_SEARCH_BASE, user_filter, attributes=['memberOf', 'distinguishedName'])

    if not conn.entries:
        print(f"User {username} not found.")
        return set()

    user_dn = conn.entries[0].distinguishedName.value
    direct_groups = conn.entries[0].memberOf.values if 'memberOf' in conn.entries[0] else []

    all_groups = set()
    groups_to_process = list(direct_groups)

    while groups_to_process:
        group_dn = groups_to_process.pop(0)
        group_name = extract_group_name(group_dn)
        all_groups.add(group_name)

        group_filter = f'(&(objectClass=group)(distinguishedName={group_dn}))'
        conn.search(AD_SEARCH_BASE, group_filter, attributes=['memberOf'])

        if conn.entries:
            parent_groups = conn.entries[0].memberOf.values if 'memberOf' in conn.entries[0] else []
            new_groups = set(parent_groups) - set(groups_to_process)
            groups_to_process.extend(list(new_groups))

    return all_groups

def extract_group_name(dn):
    match = re.match(r'CN=([^,]+)', dn)
    return match.group(1) if match else dn

def main():
    username, password = get_secure_credentials()
    conn = authenticate_user(username, password)
    
    if conn:
        # Perform your AD queries here
        # For example:
        # search_result = conn.search(...)
        # Process the search_result as needed
        username = input("Enter the username to check groups: ")
        groups = get_user_groups(username,conn)

        print(f"\nGroup memberships for user {username}:")
        for group in sorted(groups):
            print(group)
        conn.unbind()
    else:
        print("Unable to proceed without valid credentials.")

if __name__ == "__main__":
    main()
