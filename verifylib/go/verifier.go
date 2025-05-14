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

// verifyLicense checks the POW and private key, taking powListURL as an argument
func verifyLicense(powListURL string) (bool, string) {
	// Get current username to use as salt for verification
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Sprintf("Failed to get current user for verification: %v", err)
	}
	usernameSalt := currentUser.Username // This is the current machine's username

	err = godotenv.Load() // Loads .env file from the current directory
	if err != nil {
		return false, "Error loading .env file. Make sure it exists and contains POW and PRIVATE_KEY."
	}

	powFromEnv := os.Getenv("POW") // Base64 of name/project
	privateKeyEnv := os.Getenv("PRIVATE_KEY") // Salted key: sha256(sha512(POW + originalUsernameSalt))

	if powFromEnv == "" || privateKeyEnv == "" {
		return false, "POW or PRIVATE_KEY not found in .env file."
	}

	if powListURL == "" {
		return false, "powListURL argument cannot be empty."
	}

	// 1. Reconstruct the salted data for key verification using the current machine's username
	reconstructedSaltedData := powFromEnv + usernameSalt

	// 2. Calculate the expected private key
	sha512sum := sha512.Sum512([]byte(reconstructedSaltedData))
	sha256sum := sha256.Sum256(sha512sum[:])
	calculatedPrivateKey := fmt.Sprintf("%x", sha256sum)

	// 3. Compare with the private key from .env
	if calculatedPrivateKey != privateKeyEnv {
		return false, fmt.Sprintf("Private key mismatch. Verification failed using current username salt: '%s'. Ensure this software is run by the same OS user who generated the key, or the key/POW is incorrect.", usernameSalt)
	}

	// 4. Decode the POW (it's name/project)
	decodedPOWBytes, err := base64.StdEncoding.DecodeString(powFromEnv)
	if err != nil {
		return false, fmt.Sprintf("Failed to decode POW (base64): %v", err)
	}
	decodedNameProjectPart := string(decodedPOWBytes)

	// 5. Fetch the list of valid POWs (which are name/project strings)
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
		if strings.TrimSpace(scanner.Text()) == decodedNameProjectPart {
			foundInList = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Sprintf("Error reading POW list from URL: %s. Error: %v", powListURL, err)
	}

	if !foundInList {
		return false, fmt.Sprintf("Your decoded POW ('%s') was not found in the valid list at %s.", decodedNameProjectPart, powListURL)
	}

	return true, fmt.Sprintf("Verification successful (Username Salt Used for Key Check: '%s', Decoded POW: '%s').", usernameSalt, decodedNameProjectPart)
}

func main() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("Note: .env file not found. This program expects a .env file with POW and PRIVATE_KEY.")
		fmt.Println("Example .env content:")
		fmt.Println("POW=\"BASE64_OF_NAME/PROJECT\"")
		fmt.Println("PRIVATE_KEY=\"SHA256_OF_SHA512_OF_POW_PLUS_USERNAME_SALT\"")
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