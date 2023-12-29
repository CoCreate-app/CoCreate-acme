const { Client } = require('acme-client');
const fs = require('fs');

const email = 'mailto:ssl@cocreate.app';
const keyPath = 'certificates/';
let client

async function init() {
    if (!fs.existsSync(keyPath)) {
        fs.mkdirSync(keyPath, { recursive: true }); // Create the directory if it doesn't exist
    }

    const accountKeyPath = keyPath + 'account.pem';

    let accountKey;
    let isNewAccount = false; // Flag to check if the account is new

    // Check if the account key exists and load it; otherwise, create a new one
    if (!fs.existsSync(accountKeyPath)) {
        accountKey = await Client.forge.createPrivateKey();
        fs.writeFileSync(accountKeyPath, accountKey); // Store the account key
        fs.chmodSync(accountKeyPath, '400')

        isNewAccount = true; // New account, so will need to register it
    } else {
        // Load the existing account key
        accountKey = fs.readFileSync(accountKeyPath, 'utf8');
    }

    // Initialize the ACME client with the account key
    client = new Client({
        directoryUrl: Client.directory.letsencrypt.staging,
        accountKey: accountKey
    });

    // Register the new account if it was just created
    if (isNewAccount) {
        await client.createAccount({
            termsOfServiceAgreed: true,
            contact: [email]
        });
    }
}

async function requestCertificate(host, wildcard = false) {
    /* Place your domain(s) here */
    const domains = wildcard ? [host, `*.${host}`] : [host, `www.${host}`];

    /* Create certificate request */
    const [key, csr] = await Client.forge.createCsr({
        commonName: domains[0],
        altNames: domains
    });

    /* Request certificate */
    const cert = await client.auto({
        csr,
        email, // Replace with your email
        termsOfServiceAgreed: true,
        challengeCreateFn: async (authz, challenge, keyAuthorization) => {
            /* Log the URL and content for the HTTP-01 challenge */
            if (challenge.type === 'http-01') {
                const challengeUrl = `http://${authz.identifier.value}/.well-known/acme-challenge/${challenge.token}`;
                const keyAuth = keyAuthorization;


                console.log('Please create a file accessible on:');
                console.log(challengeUrl);
                console.log('With the content:');
                console.log(keyAuth);

                let file = {
                    "content-type": "text/plain",
                    "directory": "acme-challenge",
                    "host": [
                        authz.identifier.value
                    ],
                    "name": challenge.token,
                    "organization_id": "652c8d62679eca03e0b116a7",
                    "path": "/.well-known/acme-challenge/",
                    "pathname": `/.well-known/acme-challenge/${challenge.token}`,
                    "public": "true",
                    "src": keyAuth
                }
            } else if (challenge.type === 'dns-01') {
                // Calculate the DNS TXT record value
                const dnsRecordName = `_acme-challenge.${authz.identifier.value}`;
                const dnsRecordValue = await client.getChallengeKeyAuthorization(challenge);

                console.log(`Add this TXT record to your DNS:`);
                console.log(`Name: ${dnsRecordName}`);
                console.log(`Value: ${dnsRecordValue}`);

                // Here, implement the logic to add the TXT record to your DNS
                // await updateDnsTxtRecord(dnsRecordName, dnsRecordValue); // Hypothetical function to update DNS
            }

        },
        challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
            /* Clean up challenge response here if necessary */
            console.log(`Challenge removed for token: ${challenge.token}`);
            if (challenge.type === 'http-01') {
                /* Clean up challenge response here if necessary */
            } else if (challenge.type === 'dns-01') {
                // await removeDnsTxtRecord(challenge); // A hypothetical function to clean up DNS
            }

        }
    });

    /* Save the certificate and key */
    fs.writeFileSync(keyPath + 'certificate.pem', cert);
    fs.chmodSync(keyPath + 'certificate.pem', '444')

    fs.writeFileSync(keyPath + 'private-key.pem', key);
    fs.chmodSync(keyPath + 'certificate.pem', '400')

    console.log('Successfully created certificate!');
}


init().catch(err => {
    console.error('Error initializing ACME client:', err);
    // TODO: Handle initialization error (possibly retry or exit)
});

module.exports = { requestCertificate }

// requestCertificate(host).catch(err => {
//     console.error('Error creating certificate:', err);
// });
