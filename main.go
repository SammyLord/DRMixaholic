package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
)

const saltDelimiter = "#"

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Get current username to use as salt
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %v. This is needed for salting the private key.", err)
	}
	usernameSalt := currentUser.Username
	fmt.Printf("Note: Your current OS username ('%s') will be embedded in the Proof of Work.\n", usernameSalt)

	fmt.Println("Are you using this code for personal or company use? (personal/company):")
	usageType, _ := reader.ReadString('\n')
	usageType = strings.TrimSpace(strings.ToLower(usageType))

	var nameIdentifier string // Changed variable name for clarity
	if usageType == "company" {
		fmt.Print("Enter your company name: ")
		nameIdentifier, _ = reader.ReadString('\n')
		nameIdentifier = strings.TrimSpace(nameIdentifier)
	} else {
		fmt.Print("Enter your name: ")
		nameIdentifier, _ = reader.ReadString('\n')
		nameIdentifier = strings.TrimSpace(nameIdentifier)
	}

	fmt.Print("Enter the project name: ")
	projectName, _ := reader.ReadString('\n')
	projectName = strings.TrimSpace(projectName)

	if nameIdentifier == "" || projectName == "" {
		log.Fatalf("Name/Company name and Project name cannot be empty.")
	}
	// Ensure delimiter is not in username, project or nameIdentifier for simple parsing later
	if strings.Contains(usernameSalt, saltDelimiter) || strings.Contains(projectName, saltDelimiter) || strings.Contains(nameIdentifier, saltDelimiter) {
		log.Fatalf("Username, project name, or company/user name cannot contain the delimiter character: %s", saltDelimiter)
	}

	// Construct the data for POW: "name/project_name#usernameSalt"
	powDataWithSalt := fmt.Sprintf("%s/%s%s%s", nameIdentifier, projectName, saltDelimiter, usernameSalt)

	// Create the proof of work (base64 string of powDataWithSalt)
	proofOfWork := base64.StdEncoding.EncodeToString([]byte(powDataWithSalt))

	// Create the private key (sha256(sha512(proofOfWork)))
	// The salt is now part of the proofOfWork, so no extra salting here.
	sha512sum := sha512.Sum512([]byte(proofOfWork))
	sha256sum := sha256.Sum256(sha512sum[:])
	privateKey := fmt.Sprintf("%x", sha256sum)

	fmt.Println("\n--- Generated Credentials ---")
	fmt.Printf("Data embedded in POW (before base64): %s\n", powDataWithSalt)
	fmt.Println("Proof of Work (base64 - includes name, project, and username salt):", proofOfWork)
	fmt.Println("Private Key (sha256(sha512(POW))):", privateKey)

	fmt.Println("\n--- Instructions ---")
	fmt.Println("1. Your Proof of Work (POW) now represents:", powDataWithSalt)
	fmt.Println("   It has your OS username embedded. Share this Base64 encoded POW with the author.")
	fmt.Println("   The author's list will contain the part BEFORE the '#' and your username (i.e., 'name/project').")
	fmt.Println("2. Keep your Private Key secret. It is derived directly from this specific POW.")
	fmt.Println("   To verify, the software will check the key against the POW, then decode the POW to verify your username and check 'name/project' against the author's list.")
	fmt.Println("   Do NOT share your private key with anyone.")
} 