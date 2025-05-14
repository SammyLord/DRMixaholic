import os
import hashlib
import base64
import requests
from dotenv import load_dotenv
import sys
import getpass

def verify_license(pow_list_url):
    # Get current username to use as salt for verification
    try:
        current_username_salt = getpass.getuser()
    except Exception as e:
        return False, f"Failed to get current OS username for verification: {e}"

    if not load_dotenv():
        return False, "Error loading .env file. Ensure it contains POW and PRIVATE_KEY."

    pow_from_env = os.getenv("POW") # Base64 of name/project
    private_key_env = os.getenv("PRIVATE_KEY") # Salted key: sha256(sha512(POW + originalUsernameSalt))

    if not all([pow_from_env, private_key_env]):
        return False, "POW or PRIVATE_KEY not found in .env file."
    
    if not pow_list_url:
        return False, "pow_list_url argument cannot be empty."

    # 1. Reconstruct the salted data for key verification
    reconstructed_salted_data = pow_from_env + current_username_salt

    # 2. Calculate the expected private key
    sha512_hash = hashlib.sha512(reconstructed_salted_data.encode('utf-8')).digest()
    sha256_hash = hashlib.sha256(sha512_hash).hexdigest()

    # 3. Compare with the private key from .env
    if sha256_hash != private_key_env:
        return False, f"Private key mismatch. Verification failed using current username salt: '{current_username_salt}'. Ensure this software is run by the same OS user who generated the key, or the key/POW is incorrect."

    # 4. Decode the POW (it's name/project)
    try:
        decoded_pow_bytes = base64.b64decode(pow_from_env)
        decoded_name_project_part = decoded_pow_bytes.decode('utf-8')
    except Exception as e:
        return False, f"Failed to decode POW (base64). Error: {e}"

    # 5. Fetch the list of valid POWs (which are name/project strings)
    try:
        response = requests.get(pow_list_url)
        response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        return False, f"Failed to fetch POW list from URL: {pow_list_url}. Error: {e}"

    valid_pows_list = [line.strip() for line in response.text.splitlines()]

    if decoded_name_project_part not in valid_pows_list:
        return False, f"Your decoded POW ('{decoded_name_project_part}') was not found in the valid list at {pow_list_url}."

    return True, f"Verification successful (Username Salt Used for Key Check: '{current_username_salt}', Decoded POW: '{decoded_name_project_part}')."

if __name__ == "__main__":
    if not os.path.exists(".env"):
        print("Note: .env file not found. This program expects a .env file in verifylib/python/.env with POW and PRIVATE_KEY.")
        print("Example .env content:")
        print('POW="BASE64_OF_NAME/PROJECT"')
        print('PRIVATE_KEY="SHA256_OF_SHA512_OF_POW_PLUS_USERNAME_SALT"')

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