import requests
import sqlite3
import hashlib
import os
import json
from cryptography.fernet import Fernet
import ssl

def insecure_data_storage_check(db_path):
    """Checks for insecure data storage in a SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name, password FROM users")  # Example query
        results = cursor.fetchall()

        for name, password in results:
            if not password: #check if password field is empty
                print(f"[!] Insecure Data Storage: Empty password for user {name}")
            else:
                print(f"[+] User: {name} - Password (Likely Stored Insecurely): {password}")
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"[!] Database Error: {e}")
    except FileNotFoundError:
        print("[!] Database file not found.")

def insecure_communication_check(url):
    """Checks for insecure communication (HTTP instead of HTTPS)."""
    try:
        response = requests.get(url, timeout=5)
        if response.url.startswith("http://"):
            print(f"[!] Insecure Communication: {url} uses HTTP.")
        else:
            print(f"[+] Communication to {url} uses HTTPS.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Communication Error: {e}")
    except ssl.SSLCertVerificationError as e:
        print(f"[!] SSL Certificate verification error: {e}")

def insecure_authentication_check(url, username, password):
    """Checks for weak authentication (e.g., basic auth, predictable patterns)."""
    try:
        response = requests.get(url, auth=(username, password), timeout=5)
        if response.status_code == 200:
            print(f"[!] Weak Authentication: Successfully authenticated with {username}:{password}")
        elif response.status_code == 401:
            print(f"[+] Authentication failed for {username}:{password}")
        else:
            print(f"[+] Authentication check returned status code: {response.status_code}")

        # Check for common password patterns (very basic example -expand this)
        common_passwords = ["password", "123456", "admin", "1234"]
        for common_password in common_passwords:
            response_common = requests.get(url, auth=(username, common_password), timeout=5)
            if response_common.status_code == 200:
                print(f"[!] Weak Authentication: Successfully authenticated with common password: {common_password}")
                break # break to avoid multiple positives.
    except requests.exceptions.RequestException as e:
        print(f"[!] Authentication Check Error: {e}")

def main():
    """Main function to perform the security assessment."""

    # Configuration (replace with your app's details)
    db_path = "app_data.db"  # Example SQLite database path
    api_url = "http://example.com/api/login" # example api url. change to https for testing that.
    test_username = "testuser"
    test_password = "password123"

    print("[+] Starting Mobile Application Security Assessment...")

    print("\n[+] Checking Insecure Data Storage...")
    insecure_data_storage_check(db_path)

    print("\n[+] Checking Insecure Communication...")
    insecure_communication_check(api_url)

    print("\n[+] Checking Insecure Authentication...")
    insecure_authentication_check(api_url, test_username, test_password)

    print("\n[+] Security Assessment Complete.")

if __name__ == "_main_":
    main()

# Example database creation (for testing)
def create_test_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)''')
    cursor.execute("INSERT INTO users (name, password) VALUES ('user1', 'password123')")
    cursor.execute("INSERT INTO users (name, password) VALUES ('user2', '')") # example of storing an empty password
    conn.commit()
    conn.close()

create_test_db("app_data.db") # create the test database.