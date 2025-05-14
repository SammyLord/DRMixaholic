import os
import hashlib
import base64
import requests
from dotenv import load_dotenv
import sys
import getpass # Added for fetching username

def verify_license(pow_list_url):
    # Get current username to use as salt for verification
    try:
        username_salt = getpass.getuser()
    except Exception as e:
        return False, f"Failed to get current OS username for verification: {e}"

    # Load .env file from the current directory
    # Create .env file in the same directory as this script (verifylib/python/.env)
    # Example .env content:
    # POW="YOUR_BASE64_ENCODED_PROOF_OF_WORK"
    # PRIVATE_KEY="YOUR_SALTED_PRIVATE_KEY"
    if not load_dotenv():
        return False, "Error loading .env file. Make sure it exists in the same directory as the script (verifylib/python/.env) and contains POW and PRIVATE_KEY."

    pow_env = os.getenv("POW")
    private_key_env = os.getenv("PRIVATE_KEY")

    if not all([pow_env, private_key_env]):
        return False, "POW or PRIVATE_KEY not found in .env file."
    
    if not pow_list_url:
        return False, "pow_list_url argument cannot be empty."

    # 1. Reconstruct the salted POW using the current machine's username
    salted_pow = pow_env + username_salt

    # 2. Verify the private key: sha256(sha512(reconstructed saltedPOW))
    sha512_hash = hashlib.sha512(salted_pow.encode('utf-8')).digest()
    sha256_hash = hashlib.sha256(sha512_hash).hexdigest()

    if sha256_hash != private_key_env:
        return False, f"Private key mismatch. Verification failed using current username salt: '{username_salt}'. Ensure this software is run by the same OS user who generated the key."

    # 3. Decode the POW (original POW, not the salted one)
    try:
        decoded_pow_bytes = base64.b64decode(pow_env) # Use original pow_env for decoding
        decoded_pow = decoded_pow_bytes.decode('utf-8')
    except Exception as e:
        return False, f"Failed to decode POW (base64). Error: {e}"

    # 4. Fetch the list of valid POWs
    try:
        response = requests.get(pow_list_url)
        response.raise_for_status() # Raises an HTTPError for bad responses (4XX or 5XX)
    except requests.exceptions.RequestException as e:
        return False, f"Failed to fetch POW list from URL: {pow_list_url}. Error: {e}"

    valid_pows = [line.strip() for line in response.text.splitlines()]

    if decoded_pow not in valid_pows:
        return False, f"Your POW ('{decoded_pow}') was not found in the valid list at {pow_list_url}."

    return True, f"Verification successful (Username Salt: '{username_salt}')."

if __name__ == "__main__":
    if not os.path.exists(".env"):
        print("Note: .env file not found. This program expects a .env file in verifylib/python/.env with POW and PRIVATE_KEY.")
        print("Example .env content:")
        print("POW=\"YOUR_BASE64_ENCODED_PROOF_OF_WORK\"")
        print("PRIVATE_KEY=\"YOUR_SALTED_PRIVATE_KEY\"")

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