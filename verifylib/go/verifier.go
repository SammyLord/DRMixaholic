package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/joho/godotenv"
)

const saltDelimiter = "#" // Must match the delimiter in main.go

// verifyLicense checks the POW and private key, taking powListURL as an argument
func verifyLicense(powListURL string) (bool, string) {
	err := godotenv.Load()
	if err != nil {
		return false, "Error loading .env file. Ensure it contains POW and PRIVATE_KEY."
	}

	powFromEnv := os.Getenv("POW")      // This is Base64 encoded: name/project#originalUsernameSalt
	privateKeyEnv := os.Getenv("PRIVATE_KEY") // This is sha256(sha512(powFromEnv))

	if powFromEnv == "" || privateKeyEnv == "" {
		return false, "POW or PRIVATE_KEY not found in .env file."
	}
	if powListURL == "" {
		return false, "powListURL argument cannot be empty."
	}

	// 1. Verify the private key against the POW from .env
	sha512sum := sha512.Sum512([]byte(powFromEnv))
	sha256sum := sha256.Sum256(sha512sum[:])
	calculatedPrivateKey := fmt.Sprintf("%x", sha256sum)

	if calculatedPrivateKey != privateKeyEnv {
		return false, "Private key mismatch. The provided Private Key does not match the hash of the POW."
	}

	// 2. Decode the POW to get the string: name/project#originalUsernameSalt
	decodedPOWBytes, err := base64.StdEncoding.DecodeString(powFromEnv)
	if err != nil {
		return false, fmt.Sprintf("Failed to decode POW (base64): %v", err)
	}
	decodedPowStringWithSalt := string(decodedPOWBytes)

	// 3. Get current OS username
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Sprintf("Failed to get current OS username for verification: %v", err)
	}
	currentUsernameSalt := currentUser.Username

	// 4. Parse the decoded POW string to separate name/project and original salt
	parts := strings.SplitN(decodedPowStringWithSalt, saltDelimiter, 2)
	if len(parts) != 2 {
		return false, fmt.Sprintf("Failed to parse decoded POW. Expected delimiter '%s' not found or format is incorrect. Decoded: %s", saltDelimiter, decodedPowStringWithSalt)
	}
	nameProjectPart := parts[0]
	originalUsernameSalt := parts[1]

	// 5. Compare original salt from POW with current username salt
	if originalUsernameSalt != currentUsernameSalt {
		return false, fmt.Sprintf("Username mismatch. POW was generated for user '%s', but current user is '%s'.", originalUsernameSalt, currentUsernameSalt)
	}

	// 6. Fetch the list of valid POWs (which are name/project strings)
	resp, err := http.Get(powListURL)
	if err != nil {
		return false, fmt.Sprintf("Failed to fetch POW list from URL: %s. Error: %v", powListURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("Failed to fetch POW list. Status code: %d from URL: %s", resp.StatusCode, powListURL)
	}

	scanner := bufio.NewScanner(resp.Body)
	foundInList := false
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == nameProjectPart {
			foundInList = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Sprintf("Error reading POW list from URL: %s. Error: %v", powListURL, err)
	}

	if !foundInList {
		return false, fmt.Sprintf("The name/project part ('%s') from your POW was not found in the valid list at %s.", nameProjectPart, powListURL)
	}

	return true, fmt.Sprintf("Verification successful (User: '%s', Project Info: '%s').", currentUsernameSalt, nameProjectPart)
}

func main() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("Note: .env file not found. This program expects a .env file with POW and PRIVATE_KEY.")
		fmt.Println("Example .env content:")
		fmt.Println("POW=\"BASE64_OF_NAME/PROJECT#USERNAME\"")
		fmt.Println("PRIVATE_KEY=\"SHA256_OF_SHA512_OF_THE_POW_ABOVE\"")
	}

	if len(os.Args) < 2 {
		fmt.Println("Demo CLI Usage: go run verifier.go <POW_LIST_URL>")
		fmt.Println("Example: go run verifier.go https://example.com/pow_list.txt")
		os.Exit(1)
	}
	powListURLFromArg := os.Args[1]

	valid, message := verifyLicense(powListURLFromArg)
	fmt.Println(message)
	if !valid {
		os.Exit(1)
	}
	fmt.Println("License verified. Application can proceed.")
} 