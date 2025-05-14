# DRMixaholic License System

This project provides a simple system for generating and verifying software licenses. The **Proof of Work (POW)** is a Base64 encoded string of `user_or_company_name/project_name`. The **Private Key** is a double hash of this POW combined with an OS username salt (`sha256(sha512(POW + os_username_salt))`), tying the license to a specific user context for that POW.

## Why Use This?

- **Simple, Specific Licensing**: Avoids complex servers. Licenses are tied to a project (via POW) and a user context (via salted private key).
- **Proof of Legitimate Use**: The decoded POW (`user_or_company_name/project_name`) is checked against a list you manage.
- **Multi-Language Support**: Go generator; Go, Python, Node.js verifiers.

## Core Components

1.  **Key/POW Generator (`main.go`)**:
    *   Prompts for: user/company name, project name.
    *   Automatically gets the current OS username (`os_username_salt`).
    *   Creates **Proof of Work Data**: `user_or_company_name/project_name`.
    *   Generates **Proof of Work (POW)**: Base64 encoding of the Proof of Work Data.
    *   Generates **Private Key**: `sha256(sha512(POW + os_username_salt))`.

2.  **Verifier Libraries (`verifylib/`)**:
    *   Take Base64 `POW` and `PRIVATE_KEY` (from `.env` or environment).
    *   Take `POW_LIST_URL` (URL to your list of valid `user_or_company_name/project_name` strings) as an argument.
    *   **Verification Steps**:
        1.  **Get Current Username**: Fetch the OS username of the machine running the verifier (`current_os_username`).
        2.  **Reconstruct Salted Data for Key Check**: Create `data_for_key_check = POW_from_env + current_os_username`.
        3.  **Key Check**: Calculate `expected_private_key = sha256(sha512(data_for_key_check))`. Compare with `PRIVATE_KEY_from_env`. If mismatch, fail (indicates wrong key, or software run by different user than key generation).
        4.  **Decode POW**: Decode `POW_from_env` to get `decoded_name_project_part` (e.g., `User/Project`).
        5.  **POW List Check**: Fetch your list of valid `user_or_company_name/project_name` strings from `POW_LIST_URL`. Check if `decoded_name_project_part` is in this list. If not found, fail.
        6.  If all checks pass, verification is successful.

## How to Use

### 1. Setup - The POW List (Software Author)

1.  **Create `pow_list.txt`**: Contains valid `user_or_company_name/project_name` strings, one per line.
    *Example `pow_list.txt` content:*
    ```
    Alice Personal/My Cool App
    Bob Inc./Enterprise Suite
    Sammy Lord/Project DRMixaholic
    ```
2.  **Host This File Online**: Make it accessible via a public URL.

### 2. Generating POW and Private Key (End User / For End User)

1.  Run `go run main.go` in the project root.
2.  It will note the OS username being used for salting the private key (e.g., `yourusername`).
3.  Enter user/company name and project name when prompted.
4.  **Output**:
    *   **Data for POW (before base64)**: e.g., `Your Name/Your Project`.
    *   **Username Salt Used for Private Key**: The OS username incorporated into the private key.
    *   **Proof of Work (base64)**: Base64 of `Your Name/Your Project`. Share this with the software author.
    *   **Private Key (salted)**: `sha256(sha512(POW + yourusername))`. Keep this secret.
    *   Instructions explain the POW list contains `name/project`, and the key is tied to the POW and their OS username.

### 3. Verifying the License in Your Application (Software Developer)

**General Setup for Verifiers**:
*   End-user needs a `.env` file (or environment variables) with:
    *   `POW`: The Base64 encoded string of `user_or_company_name/project_name`.
    *   `PRIVATE_KEY`: The hex string private key (`sha256(sha512(POW + os_username_at_generation))`).
*   You pass your `POW_LIST_URL` to the verifier function.
*   The verifier will use the current OS username to attempt to reconstruct and validate the private key.

**A. Go Verifier (`verifylib/go/verifier.go`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_PLUS_THEIR_OS_USERNAME_AT_GENERATION"
        ```
    *   Run demo: `cd verifylib/go && go run verifier.go https://your-url.com/pow_list.txt`

**B. Python Verifier (`verifylib/python/verifier.py`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_PLUS_THEIR_OS_USERNAME_AT_GENERATION"
        ```
    *   Run demo: `cd verifylib/python && python3 verifier.py https://your-url.com/pow_list.txt` (after venv setup)

**C. Node.js Verifier (`verifylib/nodejs/verifier.js`)**
    *   `.env` example for the end-user:
        ```
        POW="BASE64_ENCODING_OF(TheirName/TheirProject)"
        PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_ABOVE_POW_PLUS_THEIR_OS_USERNAME_AT_GENERATION"
        ```
    *   Run demo: `cd verifylib/nodejs && npm install && node verifier.js https://your-url.com/pow_list.txt`

## Security Considerations

*   **Private Key Secrecy**: Critical. It's tied to the POW and the OS username at the time of generation.
*   **POW List Management**: The `pow_list.txt` contains `user_or_company_name/project_name`.
*   **Username Predictability**: OS usernames can be predictable. This salt primarily prevents accidental key sharing across different user accounts on the *same* machine or trivial sharing to other machines if the username differs. It's not a strong cryptographic defense against a determined attacker who knows the target username and has the POW.
*   **Environment Consistency**: The software must be run under the same OS username context as when the key was generated for private key verification to pass.
*   **POW List URL**: While not a secret, ensure the URL to your POW list is stable and the file itself is not tampered with.
*   **HTTPS**: Always use HTTPS for your `POW_LIST_URL` to prevent man-in-the-middle attacks when fetching the list.
*   **Simplicity vs. Robustness**: This system is still simple. The username salt adds a bit more specificity but doesn't fundamentally change its category.
*   **Revocation**: Still handled by removing the decoded POW from `pow_list.txt`.

## Contributing

Feel free to suggest improvements or report issues. 