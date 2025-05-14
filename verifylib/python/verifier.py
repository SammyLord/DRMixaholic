import os
import hashlib
import base64
import requests
from dotenv import load_dotenv
import sys
import getpass

salt_delimiter = "#" # Must match the delimiter in main.go

def verify_license(pow_list_url):
    if not load_dotenv():
        return False, "Error loading .env file. Ensure it contains POW and PRIVATE_KEY."

    pow_from_env = os.getenv("POW") # Base64: name/project#originalUsernameSalt
    private_key_env = os.getenv("PRIVATE_KEY") # sha256(sha512(pow_from_env))

    if not all([pow_from_env, private_key_env]):
        return False, "POW or PRIVATE_KEY not found in .env file."
    
    if not pow_list_url:
        return False, "pow_list_url argument cannot be empty."

    # 1. Verify the private key against the POW from .env
    sha512_hash = hashlib.sha512(pow_from_env.encode('utf-8')).digest()
    sha256_hash = hashlib.sha256(sha512_hash).hexdigest()

    if sha256_hash != private_key_env:
        return False, "Private key mismatch. The provided Private Key does not match the hash of the POW."

    # 2. Decode the POW to get the string: name/project#originalUsernameSalt
    try:
        decoded_pow_bytes = base64.b64decode(pow_from_env)
        decoded_pow_string_with_salt = decoded_pow_bytes.decode('utf-8')
    except Exception as e:
        return False, f"Failed to decode POW (base64). Error: {e}"

    # 3. Get current OS username
    try:
        current_username_salt = getpass.getuser()
    except Exception as e:
        return False, f"Failed to get current OS username for verification: {e}"

    # 4. Parse the decoded POW string
    try:
        name_project_part, original_username_salt = decoded_pow_string_with_salt.rsplit(salt_delimiter, 1)
    except ValueError:
        return False, f"Failed to parse decoded POW. Expected delimiter '{salt_delimiter}' not found or format is incorrect. Decoded: {decoded_pow_string_with_salt}"

    # 5. Compare original salt from POW with current username salt
    if original_username_salt != current_username_salt:
        return False, f"Username mismatch. POW was generated for user '{original_username_salt}', but current user is '{current_username_salt}'."

    # 6. Fetch the list of valid POWs (which are name/project strings)
    try:
        response = requests.get(pow_list_url)
        response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        return False, f"Failed to fetch POW list from URL: {pow_list_url}. Error: {e}"

    valid_pows_list = [line.strip() for line in response.text.splitlines()]

    if name_project_part not in valid_pows_list:
        return False, f"The name/project part ('{name_project_part}') from your POW was not found in the valid list at {pow_list_url}."

    return True, f"Verification successful (User: '{current_username_salt}', Project Info: '{name_project_part}')."

if __name__ == "__main__":
    if not os.path.exists(".env"):
        print("Note: .env file not found. This program expects a .env file in verifylib/python/.env with POW and PRIVATE_KEY.")
        print("Example .env content:")
        print(f'POW="BASE64_OF_NAME/PROJECT{salt_delimiter}USERNAME"')
        print(f'PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_POW_ABOVE"')

    if len(sys.argv) < 2:
        print("Demo CLI Usage: python3 verifier.py <POW_LIST_URL>")
        print("Example: python3 verifier.py https://example.com/pow_list.txt")
        sys.exit(1)
    
pow_list_url_from_arg = sys.argv[1]
        
    valid, message = verify_license(pow_list_url_from_arg)
    print(message)
    if not valid:
        sys.exit(1)
    
    print("License verified. Application can proceed.") 