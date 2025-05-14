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

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Get current username to use as salt
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %v. This is needed for salting the private key.", err)
	}
	usernameSalt := currentUser.Username
	fmt.Printf("Note: The private key will be salted with your current OS username: %s\n", usernameSalt)

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

	// Construct the data for POW: "name/project_name"
	powDataString := fmt.Sprintf("%s/%s", nameIdentifier, projectName)

	// Create the proof of work (base64 string of powDataString)
	proofOfWork := base64.StdEncoding.EncodeToString([]byte(powDataString))

	// Create the salted data for private key generation
	saltedPOWAndUser := proofOfWork + usernameSalt // Salt is applied to the base64 POW + username

	// Create the private key (sha256(sha512(saltedPOWAndUser)))
	sha512sum := sha512.Sum512([]byte(saltedPOWAndUser))
	sha256sum := sha256.Sum256(sha512sum[:])
	privateKey := fmt.Sprintf("%x", sha256sum)

	fmt.Println("\n--- Generated Credentials ---")
	fmt.Printf("Data for POW (before base64): %s\n", powDataString)
	fmt.Printf("Username Salt Used: %s\n", usernameSalt)
	fmt.Println("Proof of Work (base64):", proofOfWork)
	fmt.Println("Private Key (salted, sha256(sha512(POW + usernameSalt))):", privateKey)

	fmt.Println("\n--- Instructions ---")
	fmt.Println("1. Your Proof of Work (POW) now represents:", powDataString)
	fmt.Println("   Share the Base64 encoded POW with the author to be added to their POW list for the project.")
	fmt.Println("2. Keep your Private Key secret. It is tied to your username (", usernameSalt, ") on this machine and the specific POW.")
	fmt.Println("   To verify, the software will use the POW and the username of the computer it's running on.")
	fmt.Println("   Do NOT share your private key with anyone.")
} 