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
	usernameSalt := currentUser.Username

	err = godotenv.Load() // Loads .env file from the current directory
	if err != nil {
		return false, "Error loading .env file. Make sure it exists in the same directory as the executable and contains POW and PRIVATE_KEY."
	}

	pow := os.Getenv("POW")
	privateKeyEnv := os.Getenv("PRIVATE_KEY")

	if pow == "" || privateKeyEnv == "" {
		return false, "POW or PRIVATE_KEY not found in .env file."
	}

	if powListURL == "" {
		return false, "powListURL argument cannot be empty."
	}

	// 1. Reconstruct the salted POW using the current machine's username
	saltedPOW := pow + usernameSalt

	// 2. Verify the private key: sha256(sha512(reconstructed saltedPOW))
	sha512sum := sha512.Sum512([]byte(saltedPOW))
	sha256sum := sha256.Sum256(sha512sum[:])
	calculatedPrivateKey := fmt.Sprintf("%x", sha256sum)

	if calculatedPrivateKey != privateKeyEnv {
		return false, fmt.Sprintf("Private key mismatch. Verification failed using current username salt: %s. Ensure this software is run by the same OS user who generated the key.", usernameSalt)
	}

	// 3. Decode the POW (original POW, not the salted one)
	decodedPOWBytes, err := base64.StdEncoding.DecodeString(pow) // Use original pow for decoding
	if err != nil {
		return false, "Failed to decode POW (base64)."
	}
	decodedPOW := string(decodedPOWBytes)

	// 4. Fetch the list of valid POWs
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
		if strings.TrimSpace(scanner.Text()) == decodedPOW {
			foundInList = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Sprintf("Error reading POW list from URL: %s. Error: %v", powListURL, err)
	}

	if !foundInList {
		return false, fmt.Sprintf("Your POW ('%s') was not found in the valid list at %s.", decodedPOW, powListURL)
	}

	return true, fmt.Sprintf("Verification successful (Username Salt: %s).", usernameSalt)
}

func main() {
	// For local testing, this main function expects the POW_LIST_URL as a command-line argument.
	// In a real application, the calling code would provide this URL directly to verifyLicense.
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("Note: .env file not found. This program expects a .env file with POW and PRIVATE_KEY.")
		fmt.Println("Example .env content:")
		fmt.Println("POW=\"YOUR_BASE64_ENCODED_PROOF_OF_WORK\"")
		fmt.Println("PRIVATE_KEY=\"YOUR_SALTED_PRIVATE_KEY\"")
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