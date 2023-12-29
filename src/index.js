const { Client, forge } = require('acme-client');
const fs = require('fs');

const email = 'ssl@cocreate.app';
const keyPath = 'certificates/';
let client

class CoCreateAcme {
    constructor(crud) {
        this.crud = crud
        this.init().catch(err => {
            console.error('Error initializing ACME client:', err);
            // TODO: Handle initialization error (possibly retry or exit)
        });

    }

    async init() {
        if (!fs.existsSync(keyPath)) {
            fs.mkdirSync(keyPath, { recursive: true }); // Create the directory if it doesn't exist
        }

        const accountKeyPath = keyPath + 'account.pem';

        let accountKey = '';
        let isNewAccount = false; // Flag to check if the account is new

        // Check if the account key exists and load it; otherwise, create a new one
        if (!fs.existsSync(accountKeyPath)) {
            fs.writeFileSync(accountKeyPath, accountKey); // Store the account key
            accountKey = await forge.createPrivateKey();
            isNewAccount = true; // New account, so will need to register it
            fs.writeFileSync(accountKeyPath, accountKey); // Store the account key
            // fs.chmodSync(accountKeyPath, '400')
        } else {
            accountKey = fs.readFileSync(accountKeyPath, 'utf8');
        }

        // Initialize the ACME client with the account key
        client = new Client({
            directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
            accountKey: accountKey
        });

        // Register the new account if it was just created
        if (isNewAccount) {
            try {
                // Attempt to create an account
                await client.createAccount({
                    termsOfServiceAgreed: true,
                    contact: ['mailto:' + email]
                });
                console.log("ACME account created successfully!");
            } catch (error) {
                fs.unlinkSync(accountKeyPath)
                // Handle errors that occur during account creation
                console.error("Error creating ACME account:", error.message);
                // Depending on the type of error, you might want to retry, log the error, alert someone, etc.
            }
        }
    }

    async requestCertificate(host, organization_id, wildcard = false) {
        const self = this
        // fs.writeFileSync(keyPath + host + '/', '');
        const hostKeyPath = keyPath + host + '/';

        // Create the directory for the host if it doesn't exist
        if (!fs.existsSync(hostKeyPath)) {
            fs.mkdirSync(hostKeyPath, { recursive: true });
        }

        /* Place your domain(s) here */
        const domains = wildcard ? [host, `*.${host}`] : [host, `www.${host}`];

        /* Create certificate request */
        const [key, csr] = await forge.createCsr({
            commonName: domains[0],
            altNames: domains
        });

        fs.writeFileSync(keyPath + host + '/private-key.pem', key);

        /* Request certificate */
        const cert = await client.auto({
            csr,
            email: [email], // Replace with your email
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

                    let object = {
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
                    const client = await self.crud.send({
                        method: 'object.create',
                        array: 'files',
                        object,
                        organization_id,
                    });
                    console.log(client)

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
        fs.writeFileSync(keyPath + host + '/certificate.pem', cert);
        // fs.chmodSync(keyPath + 'certificate.pem', '444')

        fs.writeFileSync(keyPath + host + '/private-key.pem', key);
        // fs.chmodSync(keyPath + 'certificate.pem', '400')

        console.log('Successfully created certificate!');
    }

    async checkCertificate(host, organization_id) {
        if (!fs.existsSync(keyPath + host + '/certificate.pem'))
            await this.requestCertificate(host, organization_id, false)
    }

}

module.exports = CoCreateAcme;
