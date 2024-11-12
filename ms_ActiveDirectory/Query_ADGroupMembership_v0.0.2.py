import re
from ldap3 import Server, Connection, ALL, NTLM
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

AD_SERVER = os.environ.get('AD_SERVER', 'mktmp1dc01.tmk.ent.lc')
AD_SEARCH_BASE = os.environ.get('AD_SEARCH_BASE', 'DC=tmk,DC=ent,DC=lc')

def get_secure_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

def authenticate_user(username, password):
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

def extract_group_name(dn):
    match = re.match(r'CN=([^,]+)', dn)
    return match.group(1) if match else dn

def get_user_groups_hierarchy(username, conn):
    user_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
    conn.search(AD_SEARCH_BASE, user_filter, attributes=['memberOf', 'distinguishedName'])

    if not conn.entries:
        print(f"User {username} not found.")
        return {}

    user_dn = conn.entries[0].distinguishedName.value
    direct_groups = conn.entries[0].memberOf.values if 'memberOf' in conn.entries[0] else []

    hierarchy = {}
    for group_dn in direct_groups:
        hierarchy[extract_group_name(group_dn)] = get_group_hierarchy(group_dn, conn)

    return hierarchy

def get_group_hierarchy(group_dn, conn):
    group_filter = f'(&(objectClass=group)(distinguishedName={group_dn}))'
    conn.search(AD_SEARCH_BASE, group_filter, attributes=['memberOf'])

    hierarchy = {}
    if conn.entries:
        parent_groups = conn.entries[0].memberOf.values if 'memberOf' in conn.entries[0] else []
        for parent_dn in parent_groups:
            hierarchy[extract_group_name(parent_dn)] = get_group_hierarchy(parent_dn, conn)

    return hierarchy

def print_hierarchy(hierarchy, level=0):
    for group, subgroups in hierarchy.items():
        print("  " * level + "- " + group)
        print_hierarchy(subgroups, level + 1)

def main():
    username, password = get_secure_credentials()
    conn = authenticate_user(username, password)
    
    if conn:
        try:
            user_name = input("Enter the username to check groups: ")
            hierarchy = get_user_groups_hierarchy(user_name, conn)
            print(f"\nGroup hierarchy for user {user_name}:")
            print_hierarchy(hierarchy)
        finally:
            conn.unbind()
    else:
        print("Unable to proceed without valid credentials.")

if __name__ == "__main__":
    main()
