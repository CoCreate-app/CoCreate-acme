const { Client, forge } = require('acme-client');
const fs = require('fs');

const certificates = new Map()
const email = 'ssl@cocreate.app';
const keyPath = 'certificates/';
let client
const hosts = {}

// Run this once per server to generate random constants
const DAYS = Math.floor(Math.random() * 7);  // Random days between 0-6
const HOURS = Math.floor(Math.random() * 24);  // Random hours between 0-23
const MINUTES = Math.floor(Math.random() * 60);  // Random minutes between 0-59

// Store these constants in a configuration file, environment variable, or database

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
        try {

            const self = this

            const hostKeyPath = keyPath + host + '/';
            if (!fs.existsSync(hostKeyPath)) {
                fs.mkdirSync(hostKeyPath, { recursive: true });
            }

            const domains = wildcard ? [host, `*.${host}`] : [host];

            /* Create certificate request */
            const [key, csr] = await forge.createCsr({
                commonName: domains[0],
                altNames: domains
            });

            let challenge_id = ''

            /* Request certificate */
            const cert = await client.auto({
                csr,
                email: [email], // Replace with your email
                termsOfServiceAgreed: true,
                challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                    if (challenge.type === 'http-01') {
                        const httpChallenge = await self.crud.send({
                            method: 'object.create',
                            array: 'files',
                            object: {
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
                                "src": keyAuthorization
                            },
                            organization_id,
                        });

                        if (httpChallenge && httpChallenge.object && httpChallenge.object[0])
                            challenge_id = httpChallenge.object[0]._id
                        else
                            console.error('error creating challenge url')

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
                        self.crud.send({
                            method: 'object.delete',
                            array: 'files',
                            object: {
                                _id: challenge_id
                            },
                            organization_id,
                        });
                    } else if (challenge.type === 'dns-01') {
                        // await removeDnsTxtRecord(challenge); // A hypothetical function to clean up DNS
                    }

                }
            });

            let expires = await forge.readCertificateInfo(cert);
            expires = expires.notAfter;
            certificates.set(host, expires)

            /* Save the certificate and key */
            fs.writeFileSync(hostKeyPath + 'certificate.pem', cert);
            // fs.chmodSync(keyPath + 'certificate.pem', '444')

            fs.writeFileSync(hostKeyPath + 'private-key.pem', key);
            // fs.chmodSync(keyPath + 'certificate.pem', '400')

            // TODO: emit change so that nginx can reload

            let safeKey = host.replace(/\./g, '_');
            let organization = await this.crud.send({
                method: 'object.update',
                array: 'organizations',
                object: {
                    _id: organization_id,
                    ['ssl.' + safeKey]: { cert, key: key.toString('utf-8') }
                },
                organization_id,
            });

            console.log('Successfully created certificate!');
            return true
        } catch (error) {
            delete hosts[host]
            return false
        }

    }

    async getCertificate(host, organization_id) {
        const hostKeyPath = keyPath + host + '/';

        let organization = await this.crud.send({
            method: 'object.read',
            array: 'organizations',
            object: {
                _id: organization_id
            },
            organization_id,
        });

        if (organization && organization.object && organization.object[0]) {

            if (!organization.object[0].host || !organization.object[0].host.includes(host))
                return false

            let safeKey = host.replace(/\./g, '_');
            if (organization.object[0].ssl && organization.object[0].ssl[safeKey]) {
                let cert = organization.object[0].ssl[safeKey].cert
                let key = organization.object[0].ssl[safeKey].key
                if (cert && key) {
                    let expires = await forge.readCertificateInfo(cert);
                    expires = expires.notAfter;
                    if (this.isValid(expires)) {
                        certificates.set(host, expires)
                        if (!fs.existsSync(hostKeyPath)) {
                            fs.mkdirSync(hostKeyPath, { recursive: true });
                        }

                        fs.writeFileSync(hostKeyPath + 'certificate.pem', cert);
                        // fs.chmodSync(keyPath + 'certificate.pem', '444')
                        fs.writeFileSync(hostKeyPath + 'private-key.pem', key);
                        // fs.chmodSync(keyPath + 'certificate.pem', '400')

                        // TODO: emit change so that nginx can reload
                        return true
                    }
                }
            }
        }

        return await this.requestCertificate(host, organization_id, false)
    }

    isValid(expires) {
        let currentDate = new Date();
        currentDate.setDate(currentDate.getDate() + DAYS);
        currentDate.setHours(currentDate.getHours() + HOURS);
        currentDate.setMinutes(currentDate.getMinutes() + MINUTES);

        if (expires && currentDate < expires) {
            return true; // SSL is still valid, no need to renew
        }
    }

    async checkCertificate(host, organization_id) {
        let hostname = host.split(':')[0]
        if (hostname === 'localhost' || hostname === '127.0.0.1')
            return true

        let expires = certificates.get(host)
        if (expires && this.isValid(expires)) {
            return true
        }

        const hostKeyPath = keyPath + host + '/';
        if (fs.existsSync(hostKeyPath + 'certificate.pem')) {
            expires = fs.readFileSync(hostKeyPath + 'certificate.pem', 'utf8');
            expires = await forge.readCertificateInfo(expires);
            expires = expires.notAfter;
            if (this.isValid(expires)) {
                certificates.set(host, expires)
                return true
            }
        }

        if (!hosts[host])
            hosts[host] = this.getCertificate(host, organization_id)
        return hosts[host]
    }

}

module.exports = CoCreateAcme;
