const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const saltDelimiter = "#"; // Must match the delimiter in main.go

function loadEnv(filePath = '.env') {
    const envPath = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(envPath)) {
        console.log(`Note: .env file not found at ${envPath}. This script expects a .env file with POW and PRIVATE_KEY.`);
        console.log(`Example .env content for verifylib/nodejs/.env:`);
        console.log(`POW="BASE64_OF_NAME/PROJECT${saltDelimiter}USERNAME"`);
        console.log(`PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_POW_ABOVE"`);
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
    if (!loadEnv(path.join(__dirname, '.env'))) {
        // Message already printed by loadEnv if .env is missing
    }

    const powFromEnv = process.env.POW; // Base64: name/project#originalUsernameSalt
    const privateKeyEnv = process.env.PRIVATE_KEY; // sha256(sha512(powFromEnv))

    if (!powFromEnv || !privateKeyEnv) {
        return { valid: false, message: "POW or PRIVATE_KEY not found in environment variables. Make sure .env file is correctly set up." };
    }

    if (!powListUrlFromArg) {
        return { valid: false, message: "powListUrlFromArg argument cannot be empty." };
    }

    // 1. Verify the private key against the POW from .env
    const sha512Hash = crypto.createHash('sha512').update(powFromEnv).digest();
    const sha256Hash = crypto.createHash('sha256').update(sha512Hash).digest('hex');

    if (sha256Hash !== privateKeyEnv) {
        return { valid: false, message: "Private key mismatch. The provided Private Key does not match the hash of the POW." };
    }

    // 2. Decode the POW to get the string: name/project#originalUsernameSalt
    let decodedPowStringWithSalt;
    try {
        decodedPowStringWithSalt = Buffer.from(powFromEnv, 'base64').toString('utf-8');
    } catch (e) {
        return { valid: false, message: `Failed to decode POW (base64). Error: ${e.message}` };
    }

    // 3. Get current OS username
    let currentUsernameSalt;
    try {
        currentUsernameSalt = os.userInfo().username;
    } catch (e) {
        return { valid: false, message: `Failed to get current OS username for verification: ${e.message}` };
    }

    // 4. Parse the decoded POW string
    const delimiterIndex = decodedPowStringWithSalt.lastIndexOf(saltDelimiter);
    if (delimiterIndex === -1) {
        return { valid: false, message: `Failed to parse decoded POW. Expected delimiter '${saltDelimiter}' not found or format is incorrect. Decoded: ${decodedPowStringWithSalt}` };
    }
    const nameProjectPart = decodedPowStringWithSalt.substring(0, delimiterIndex);
    const originalUsernameSalt = decodedPowStringWithSalt.substring(delimiterIndex + 1);

    // 5. Compare original salt from POW with current username salt
    if (originalUsernameSalt !== currentUsernameSalt) {
        return { valid: false, message: `Username mismatch. POW was generated for user '${originalUsernameSalt}', but current user is '${currentUsernameSalt}'.` };
    }

    // 6. Fetch the list of valid POWs (which are name/project strings)
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

    const validPowsList = response.data.split('\n').map(line => line.trim());

    if (!validPowsList.includes(nameProjectPart)) {
        return { valid: false, message: `The name/project part ('${nameProjectPart}') from your POW was not found in the valid list at ${powListUrlFromArg}.` };
    }

    return { valid: true, message: `Verification successful (User: '${currentUsernameSalt}', Project Info: '${nameProjectPart}').` };
}

async function main() {
    if (process.argv.length < 3) {
        console.log("Demo CLI Usage: node verifier.js <POW_LIST_URL>");
        console.log("Example: node verifier.js https://example.com/pow_list.txt");
        // Check for .env and print example if missing, as it's crucial now.
        const envPath = path.join(__dirname, '.env');
        if (!fs.existsSync(envPath)) {
            console.log("\nNote: .env file not found. This program expects a .env file in verifylib/nodejs/.env with POW and PRIVATE_KEY.")
            console.log("Example .env content:");
            console.log(`POW="BASE64_OF_NAME/PROJECT${saltDelimiter}USERNAME"`);
            console.log(`PRIVATE_KEY="SHA256_OF_SHA512_OF_THE_POW_ABOVE"`);
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