# DRMixaholic License System

This project provides a simple system for generating and verifying software licenses. It's designed for developers who want a straightforward way to issue a proof-of-work (POW) and a corresponding private key for software access. The POW incorporates a **user/company name and a project name**. The private key is salted with the OS username of the computer where it's generated, tying the license to that specific user context for that project.

## Why Use This?

- **Simple Licensing**: Avoids complex licensing servers for basic use cases.
- **User-Specific & Project-Specific Keys**: Licenses are tied to the username on the machine where the key was generated and the specific project name provided, adding layers of specificity.
- **Proof of Legitimate Use**: The POW (e.g., `User Name/Project Name`) can be a publicly listed identifier that you manage.
- **Offline Verification (Core Logic)**: The core cryptographic check (POW + OS username salt vs. Private Key) is self-contained.
- **Online POW List Check**: Verification still includes checking the decoded POW (e.g., `User Name/Project Name`) against a list you maintain online.
- **Multi-Language Support**: Includes a key generator in Go and verifier libraries in Go, Python, and Node.js.

## Core Components

1.  **Key/POW Generator (`main.go`)**: A Go application that prompts for a user/company name, a project name, and then generates:
    *   **Proof of Work Data**: A string formatted as `user_or_company_name/project_name`.
    *   **Proof of Work (POW)**: The Base64 encoded string of the Proof of Work Data. This is shared with the software author.
    *   **Private Key**: A SHA256 hash of a SHA512 hash of the `Base64_POW + os_username_salt`. The `os_username_salt` is the username of the OS user running the generator. This key is kept secret by the end-user.

2.  **Verifier Libraries (`verifylib/`)**: Libraries in Go, Python, and Node.js that perform the verification process:
    *   They take a Base64 POW and a Private Key (from `.env` or environment variables).
    *   They take the URL of your publicly hosted POW list as an argument.
    *   They automatically fetch the current OS username for salting.
    *   **Verification Steps**:
        1.  Fetch the current OS username (`currentUserSalt`).
        2.  Reconstruct the salted data for key checking: `Base64_POW_from_env + currentUserSalt`.
        3.  Recalculate a private key from this reconstructed salted data using `sha256(sha512(salted_data))`.
        4.  Compare this recalculated private key with the `PRIVATE_KEY_from_env`. If they don't match, verification fails.
        5.  Decode the `Base64_POW_from_env`. This should result in the original `user_or_company_name/project_name` string.
        6.  Fetch the list of valid POW data strings (e.g., `User1/ProjectA`, `CompanyX/ProjectB`) from the provided URL.
        7.  Check if the decoded POW data string exists in the fetched list. If not, verification fails.
        8.  If all checks pass, verification is successful.

## How to Use

### 1. Setup - The POW List (Software Author)

1.  **Create a Plaintext File**: This file will contain all valid **decoded** POW data strings (i.e., `user_or_company_name/project_name`), one per line.
    *Example `pow_list.txt` content:*
    ```
    Alice Personal/My Cool App
    Bob Inc./Enterprise Suite
    Charlie Company/Data Tool
    Sammy Lord/Project DRMixaholic
    ```
2.  **Host This File Online**: Make it accessible via a public URL.

### 2. Generating POW and Private Key (End User / For End User)

**Prerequisites**: Go installed.

**Steps**:
1.  Navigate to the root directory (`DRMixaholic`).
2.  Run `go run main.go`.
3.  The application will first note the OS username being used as a salt.
4.  It will then prompt for:
    *   Personal or company use.
    *   User or company name.
    *   **Project name**.
5.  It will output:
    *   **Data for POW (before base64)**: e.g., `Your Name/Your Project`.
    *   **Username Salt Used**.
    *   **Proof of Work (base64)**: The Base64 of `Your Name/Your Project`. Share this with the software author.
    *   **Private Key (salted)**: Keep this secret. It's tied to the specific POW (including project name) and your OS username.

### 3. Verifying the License in Your Application (Software Developer)

**General Setup for Verifiers**:
*   End-user application needs `POW` (the Base64 string) and `PRIVATE_KEY` (the salted hex string) in its environment or `.env` file.
*   You pass the `POW_LIST_URL` to the verifier function.
*   The verifier uses the current OS username to attempt to match the salted private key.
*   The verifier decodes the POW and expects to find the resulting `user_name/project_name` string in your `pow_list.txt`.

**(Demo CLI usage instructions for Go, Python, Node.js remain largely the same, with the understanding that the POW in `.env` is now for `name/project` and the `pow_list.txt` must match this decoded format).**

**A. Go Verifier (`verifylib/go/verifier.go`)**
    *   `.env` file for end-user:
        ```
        POW="BASE64_OF_THEIR_NAME_AND_PROJECT_NAME"
        PRIVATE_KEY="THEIR_SALTED_PRIVATE_KEY_STRING"
        ```
    *   Run: `go run verifier.go https://your-url.com/pow_list.txt`

**B. Python Verifier (`verifylib/python/verifier.py`)**
    *   `.env` file for end-user:
        ```
        POW="BASE64_OF_THEIR_NAME_AND_PROJECT_NAME"
        PRIVATE_KEY="THEIR_SALTED_PRIVATE_KEY_STRING"
        ```
    *   Run: `python3 verifier.py https://your-url.com/pow_list.txt`

**C. Node.js Verifier (`verifylib/nodejs/verifier.js`)**
    *   `.env` file for end-user:
        ```
        POW="BASE64_OF_THEIR_NAME_AND_PROJECT_NAME"
        PRIVATE_KEY="THEIR_SALTED_PRIVATE_KEY_STRING"
        ```
    *   Run: `node verifier.js https://your-url.com/pow_list.txt`

## Security Considerations

*   **Specificity**: The license is now specific to a user (via OS username salt) AND a project name (embedded in the POW).
*   **POW List Management**: Your `pow_list.txt` now needs to be managed with `user_name/project_name` entries.
*   **Private Key Secrecy**: Still paramount. The key is now also tied to the OS username.
*   **Username Predictability**: OS usernames can sometimes be predictable (e.g., 'admin', 'user'). This salt primarily prevents accidental key sharing across different user accounts on the *same* machine or trivial sharing to other machines if the username differs. It's not a strong cryptographic defense against a determined attacker who knows the target username.
*   **Environment Consistency**: The software must be run under the same OS username context as when the key was generated for verification to pass. This might affect how users run the software (e.g., via specific user accounts, services running as a particular user).
*   **POW List URL**: While not a secret, ensure the URL to your POW list is stable and the file itself is not tampered with.
*   **HTTPS**: Always use HTTPS for your `POW_LIST_URL` to prevent man-in-the-middle attacks when fetching the list.
*   **Simplicity vs. Robustness**: This system is still simple. The username salt adds a bit more specificity but doesn't fundamentally change its category.
*   **Revocation**: Still handled by removing the decoded POW from `pow_list.txt`.

## Contributing

Feel free to suggest improvements or report issues. 