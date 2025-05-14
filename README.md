# DRMixaholic License System

This project provides a system for generating and verifying software licenses. The **Proof of Work (POW)** itself is a Base64 encoded string containing `user_or_company_name/project_name#os_username_salt`, making the POW inherently tied to a user and project. The **Private Key** is a direct double hash of this POW.

## Why Use This?

- **Simple, Specific Licensing**: Avoids complex servers. Licenses are tied to user, project, and the machine context (OS username) where the key was generated.
- **Proof of Legitimate Use**: The decoded part of the POW (`user_or_company_name/project_name`) is checked against a list you manage.
- **Multi-Language Support**: Go generator; Go, Python, Node.js verifiers.

## Core Components

1.  **Key/POW Generator (`main.go`)**:
    *   Prompts for: user/company name, project name.
    *   Automatically gets the current OS username (`os_username_salt`).
    *   Creates **Proof of Work Data**: `user_or_company_name/project_name#os_username_salt`.
    *   Generates **Proof of Work (POW)**: Base64 encoding of the Proof of Work Data.
    *   Generates **Private Key**: `sha256(sha512(POW))`.

2.  **Verifier Libraries (`verifylib/`)**:
    *   Take Base64 `POW` and `PRIVATE_KEY` (from `.env` or environment).
    *   Take `POW_LIST_URL` (URL to your list of valid `user_or_company_name/project_name` strings) as an argument.
    *   **Verification Steps**:
        1.  **Key Check**: Calculate `expected_private_key = sha256(sha512(POW_from_env))`. Compare with `PRIVATE_KEY_from_env`. If mismatch, fail.
        2.  **Decode POW**: Decode `POW_from_env` to get the `decoded_pow_string` (e.g., `User/Project#generating_username`).
        3.  **Get Current Username**: Fetch the OS username of the machine running the verifier (`current_os_username`).
        4.  **Parse Decoded POW**: Split `decoded_pow_string` at the last `#` to get `name_project_part` (e.g., `User/Project`) and `original_os_username_salt` (e.g., `generating_username`).
        5.  **Username Match**: Compare `original_os_username_salt` with `current_os_username`. If mismatch, fail.
        6.  **POW List Check**: Fetch your list of valid `user_or_company_name/project_name` strings from `POW_LIST_URL`. Check if `name_project_part` is in this list. If not found, fail.
        7.  If all checks pass, verification is successful.

## How to Use

### 1. Setup - The POW List (Software Author)

1.  **Create `pow_list.txt`**: Contains valid `user_or_company_name/project_name` strings, one per line. **Do not include the `#os_username_salt` part here.**
    *Example `pow_list.txt` content:*
    ```
    Alice Personal/My Cool App
    Bob Inc./Enterprise Suite
    Sammy Lord/Project DRMixaholic
    ```
2.  **Host This File Online**: Make it accessible via a public URL.

### 2. Generating POW and Private Key (End User / For End User)

1.  Run `go run main.go` in the project root.
2.  It will note the OS username being used (e.g., `yourusername`).
3.  Enter user/company name and project name when prompted.
4.  **Output**:
    *   **Data embedded in POW (before base64)**: e.g., `Your Name/Your Project#yourusername`.
    *   **Proof of Work (base64)**: Base64 of the above. Share this with the software author.
    *   **Private Key**: `sha256(sha512(POW))`. Keep this secret.
    *   Instructions explain that the POW list contains the `name/project` part, and the key is tied to the full POW (which includes their username).

### 3. Verifying the License in Your Application (Software Developer)

**General Setup for Verifiers**:
*   End-user needs a `.env` file (or environment variables) with:
    *   `POW`: The full Base64 encoded string (`user_or_company_name/project_name#generating_os_username`).
    *   `PRIVATE_KEY`: The hex string private key derived from that full POW.
*   You pass your `POW_LIST_URL` to the verifier function.

**A. Go Verifier (`verifylib/go/verifier.go`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject#their_os_username_at_generation)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_STRING"
        ```
    *   Run demo: `cd verifylib/go && go run verifier.go https://your-url.com/pow_list.txt`

**B. Python Verifier (`verifylib/python/verifier.py`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject#their_os_username_at_generation)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_STRING"
        ```
    *   Run demo: `cd verifylib/python && python3 verifier.py https://your-url.com/pow_list.txt` (after venv setup)

**C. Node.js Verifier (`verifylib/nodejs/verifier.js`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject#their_os_username_at_generation)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_STRING"
        ```
    *   Run demo: `cd verifylib/nodejs && npm install && node verifier.js https://your-url.com/pow_list.txt`

## Security Considerations

*   **POW is User-Specific**: The POW itself is now tied to the generating OS username. Sharing the POW and Private Key pair means the recipient must also run the software under the *original generating OS username* for it to work.
*   **POW List Management**: The `pow_list.txt` contains the `user_or_company_name/project_name` part, *not* the username salt. This list authorizes specific user/project combinations.
*   **Private Key Secrecy**: Critical. It's a direct derivative of the user-and-project-specific POW.
*   **Username Predictability**: OS usernames can sometimes be predictable (e.g., 'admin', 'user'). This salt primarily prevents accidental key sharing across different user accounts on the *same* machine or trivial sharing to other machines if the username differs. It's not a strong cryptographic defense against a determined attacker who knows the target username.
*   **Environment Consistency**: The software must be run under the same OS username context as when the key was generated for verification to pass. This might affect how users run the software (e.g., via specific user accounts, services running as a particular user).
*   **POW List URL**: While not a secret, ensure the URL to your POW list is stable and the file itself is not tampered with.
*   **HTTPS**: Always use HTTPS for your `POW_LIST_URL` to prevent man-in-the-middle attacks when fetching the list.
*   **Simplicity vs. Robustness**: This system is still simple. The username salt adds a bit more specificity but doesn't fundamentally change its category.
*   **Revocation**: Still handled by removing the decoded POW from `pow_list.txt`.

## Contributing

Feel free to suggest improvements or report issues. 