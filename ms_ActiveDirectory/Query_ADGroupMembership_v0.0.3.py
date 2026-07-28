import re
import ssl
import hashlib
from ldap3 import Server, Connection, ALL, NTLM
from ldap3.utils.conv import escape_filter_chars
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

AD_SERVER = os.environ.get('AD_SERVER', 'mktmp1dc01.tmk.ent.lc')
AD_SEARCH_BASE = os.environ.get('AD_SEARCH_BASE', 'DC=tmk,DC=ent,DC=lc')

class SecureString:
    def __init__(self, plaintext):
        self.key = self._generate_key()
        self.encrypted = self._encrypt(plaintext)

    def _generate_key(self):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))

    def _encrypt(self, plaintext):
        f = Fernet(self.key)
        return f.encrypt(plaintext.encode())

    def decrypt(self):
        f = Fernet(self.key)
        return f.decrypt(self.encrypted).decode()

    def __str__(self):
        return "[ENCRYPTED]"

    def __repr__(self):
        return "[ENCRYPTED]"

def get_secure_input(prompt):
    return SecureString(getpass.getpass(prompt))

def patch_crypto_be_discovery():
    """
    Monkey patches cryptography's backend detection.
    Objective: support MD4 hashing on OpenSSL 3.0.0+
    """
    from cryptography.hazmat import backends
    try:
        from cryptography.hazmat.backends.openssl.backend import backend as be_backend
    except ImportError:
        be_backend = None
    backends._available_backends_list = [be_backend]


def get_secure_credentials():
    username = input("Enter your username: ")
    password = get_secure_input("Enter your password: ")
    return username, password

def authenticate_user(username, password):
    try:
        server = Server(AD_SERVER, get_info=ALL,use_ssl=True)
        escaped_username = escape_filter_chars(username)
        escaped_password = escape_filter_chars(password)
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
    patch_crypto_be_discovery()
    username, password = get_secure_credentials()
    conn = authenticate_user(username, password.decrypt())
    
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
