const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os'); // Added for fetching username

// Function to load .env variables manually for wider compatibility
// In a typical Node project, you'd just use `require('dotenv').config()`
// but this makes it more self-contained if `dotenv` isn't installed globally.
function loadEnv(filePath = '.env') {
    const envPath = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(envPath)) {
        console.log(`Note: .env file not found at ${envPath}. This script expects a .env file with POW and PRIVATE_KEY.`);
        console.log(`Example .env content for verifylib/nodejs/.env:`);
        console.log(`POW="YOUR_BASE64_ENCODED_PROOF_OF_WORK"`);
        console.log(`PRIVATE_KEY="YOUR_SALTED_PRIVATE_KEY"`);
        return false;
    }
    const fileContent = fs.readFileSync(envPath, { encoding: 'utf8' });
    fileContent.split('\n').forEach(line => {
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('#')) {
            const [key, ...valueParts] = trimmedLine.split('=');
            const value = valueParts.join('=').replace(/^["']|["']$/g, '');
            if (key) {
                process.env[key.trim()] = value.trim();
            }
        }
    });
    return true;
}

async function verifyLicense(powListUrlFromArg) {
    let usernameSalt;
    try {
        usernameSalt = os.userInfo().username;
    } catch (e) {
        return { valid: false, message: `Failed to get current OS username for verification: ${e.message}` };
    }

    if (!loadEnv(path.join(__dirname, '.env'))) {
        // Message already printed by loadEnv if .env is missing
    }

    const powEnv = process.env.POW;
    const privateKeyEnv = process.env.PRIVATE_KEY;

    if (!powEnv || !privateKeyEnv) {
        return { valid: false, message: "POW or PRIVATE_KEY not found in environment variables. Make sure .env file is correctly set up in verifylib/nodejs/.env." };
    }

    if (!powListUrlFromArg) {
        return { valid: false, message: "powListUrlFromArg argument cannot be empty." };
    }

    // 1. Reconstruct the salted POW using the current machine's username
    const saltedPOW = powEnv + usernameSalt;

    // 2. Verify the private key: sha256(sha512(reconstructed saltedPOW))
    const sha512Hash = crypto.createHash('sha512').update(saltedPOW).digest();
    const sha256Hash = crypto.createHash('sha256').update(sha512Hash).digest('hex');

    if (sha256Hash !== privateKeyEnv) {
        return { valid: false, message: `Private key mismatch. Verification failed using current username salt: '${usernameSalt}'. Ensure this software is run by the same OS user who generated the key.` };
    }

    // 3. Decode the POW (original POW, not the salted one)
    let decodedPow;
    try {
        decodedPow = Buffer.from(powEnv, 'base64').toString('utf-8'); // Use original powEnv for decoding
    } catch (e) {
        return { valid: false, message: `Failed to decode POW (base64). Error: ${e.message}` };
    }

    // 4. Fetch the list of valid POWs
    let response;
    try {
        const { default: axios } = await import('axios');
        response = await axios.get(powListUrlFromArg);
        if (response.status !== 200) {
            return { valid: false, message: `Failed to fetch POW list. Status code: ${response.status} from URL: ${powListUrlFromArg}` };
        }
    } catch (e) {
        return { valid: false, message: `Failed to fetch POW list from URL: ${powListUrlFromArg}. Error: ${e.message}` };
    }

    const validPows = response.data.split('\n').map(line => line.trim());

    if (!validPows.includes(decodedPow)) {
        return { valid: false, message: `Your POW ('${decodedPow}') was not found in the valid list at ${powListUrlFromArg}.` };
    }

    return { valid: true, message: `Verification successful (Username Salt: '${usernameSalt}').` };
}

async function main() {
    if (process.argv.length < 3) {
        console.log("Demo CLI Usage: node verifier.js <POW_LIST_URL>");
        console.log("Example: node verifier.js https://example.com/pow_list.txt");
        if (!fs.existsSync(path.join(__dirname, '.env'))) {
            console.log("\nNote: .env file not found. This program expects a .env file in verifylib/nodejs/.env with POW and PRIVATE_KEY.")
            console.log("Example .env content:");
            console.log("POW=\"YOUR_BASE64_ENCODED_PROOF_OF_WORK\"");
            console.log("PRIVATE_KEY=\"YOUR_SALTED_PRIVATE_KEY\"");
        }
        process.exit(1);
    }
    const powListURLFromArg = process.argv[2];

    const result = await verifyLicense(powListURLFromArg);
    console.log(result.message);
    if (!result.valid) {
        process.exit(1);
    }
    console.log("License verified. Application can proceed.");
}

main(); 