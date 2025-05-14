const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

function loadEnv(filePath = '.env') {
    const envPath = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(envPath)) {
        console.log(`Note: .env file not found at ${envPath}. This script expects a .env file with POW and PRIVATE_KEY.`);
        console.log(`Example .env content for verifylib/nodejs/.env:`);
        console.log('POW="BASE64_OF_NAME/PROJECT"');
        console.log('PRIVATE_KEY="SHA256_OF_SHA512_OF_POW_PLUS_USERNAME_SALT"');
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
    let currentUsernameSalt;
    try {
        currentUsernameSalt = os.userInfo().username;
    } catch (e) {
        return { valid: false, message: `Failed to get current OS username for verification: ${e.message}` };
    }

    if (!loadEnv(path.join(__dirname, '.env'))) {
        // Message already printed by loadEnv if .env is missing
    }

    const powFromEnv = process.env.POW; // Base64 of name/project
    const privateKeyEnv = process.env.PRIVATE_KEY; // Salted key: sha256(sha512(POW + originalUsernameSalt))

    if (!powFromEnv || !privateKeyEnv) {
        return { valid: false, message: "POW or PRIVATE_KEY not found in environment variables. Make sure .env file is correctly set up." };
    }

    if (!powListUrlFromArg) {
        return { valid: false, message: "powListUrlFromArg argument cannot be empty." };
    }

    // 1. Reconstruct the salted data for key verification
    const reconstructedSaltedData = powFromEnv + currentUsernameSalt;

    // 2. Calculate the expected private key
    const sha512Hash = crypto.createHash('sha512').update(reconstructedSaltedData).digest();
    const sha256Hash = crypto.createHash('sha256').update(sha512Hash).digest('hex');

    // 3. Compare with the private key from .env
    if (sha256Hash !== privateKeyEnv) {
        return { valid: false, message: `Private key mismatch. Verification failed using current username salt: '${currentUsernameSalt}'. Ensure this software is run by the same OS user who generated the key, or the key/POW is incorrect.` };
    }

    // 4. Decode the POW (it's name/project)
    let decodedNameProjectPart;
    try {
        decodedNameProjectPart = Buffer.from(powFromEnv, 'base64').toString('utf-8');
    } catch (e) {
        return { valid: false, message: `Failed to decode POW (base64). Error: ${e.message}` };
    }

    // 5. Fetch the list of valid POWs (which are name/project strings)
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

    if (!validPowsList.includes(decodedNameProjectPart)) {
        return { valid: false, message: `Your decoded POW ('${decodedNameProjectPart}') was not found in the valid list at ${powListUrlFromArg}.` };
    }

    return { valid: true, message: `Verification successful (Username Salt Used for Key Check: '${currentUsernameSalt}', Decoded POW: '${decodedNameProjectPart}').` };
}

async function main() {
    if (process.argv.length < 3) {
        console.log("Demo CLI Usage: node verifier.js <POW_LIST_URL>");
        console.log("Example: node verifier.js https://example.com/pow_list.txt");
        const envPath = path.join(__dirname, '.env');
        if (!fs.existsSync(envPath)) {
            console.log("\nNote: .env file not found. This program expects a .env file in verifylib/nodejs/.env with POW and PRIVATE_KEY.")
            console.log("Example .env content:");
            console.log('POW="BASE64_OF_NAME/PROJECT"');
            console.log('PRIVATE_KEY="SHA256_OF_SHA512_OF_POW_PLUS_USERNAME_SALT"');
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