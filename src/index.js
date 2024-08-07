const { Client, forge } = require('acme-client');
const fs = require('fs');
const util = require('node:util');
const exec = util.promisify(require('node:child_process').exec);

const certificates = {}
const email = 'ssl@cocreate.app';
const keyPath = '/etc/certificates/';
let client
const hosts = {}

// Run this once per server to generate random constants
const DAYS = Math.floor(Math.random() * 7);  // Random days between 0-6
const HOURS = Math.floor(Math.random() * 24);  // Random hours between 0-23
const MINUTES = Math.floor(Math.random() * 60);  // Random minutes between 0-59

// Store these constants in a configuration file, environment variable, or database

class CoCreateAcme {
    constructor(proxy, crud) {
        this.proxy = proxy
        this.crud = crud
        // this.check = this.checkCertificate
        this.init().catch(err => {
            console.error('Error initializing ACME client:', err);
            // TODO: Handle initialization error (possibly retry or exit)
        });

    }

    async init() {
        await exec('sudo mkdir -p /etc/certificates');
        await exec('sudo chmod 777 /etc/certificates');

        // if (!fs.existsSync(keyPath)) {
        //     fs.mkdirSync(keyPath, { recursive: true }); // Create the directory if it doesn't exist
        // }

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
            directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory', // https://acme-v02.api.letsencrypt.org/directory https://acme-staging-v02.api.letsencrypt.org/directory
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

    async requestCertificate(host, hostPosition, hostObject, organization_id, wildcard = false) {
        try {

            const self = this

            const hostKeyPath = keyPath + host + '/';
            if (!fs.existsSync(hostKeyPath)) {
                fs.mkdirSync(hostKeyPath, { recursive: true });
            }

            const domains = wildcard ? [host, `*.${host}`] : [host];

            /* Create certificate request */
            let [key, csr] = await forge.createCsr({
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
                    console.log(`Challenge added for host: ${host} token: ${challenge.token}`);

                    if (challenge.type === 'http-01') {
                        const httpChallenge = await self.crud.send({
                            method: 'object.create',
                            host,
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
                            host,
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
            this.setCertificate(host, expires, organization_id, hostKeyPath, cert, key)

            key = key.toString('utf8');

            this.crud.send({
                method: 'object.update',
                host,
                array: 'organizations',
                object: {
                    _id: organization_id,
                    [`host[${hostPosition}]`]: { ...hostObject, name: host, cert, key, expires },
                },
                organization_id
            });

            console.log(`Certificate successfully created for ${host}!'`);
            return true
        } catch (error) {
            console.log(`Certificate failed to create for ${host}!`);
            delete hosts[host]
            return false
        }

    }

    async getCertificate(host, organization_id) {
        const hostKeyPath = keyPath + host + '/';
        let hostPosition, hostObject

        let organization = await this.crud.getOrganization({ host, organization_id });
        if (organization.error)
            return false
        if (!organization_id)
            organization_id = organization._id

        if (organization.host) {
            for (let i = 0; i < organization.host.length; i++) {
                if (organization.host[i].name === host) {
                    hostPosition = i
                    hostObject = organization.host[i]
                    if (organization.host[i].cert && organization.host[i].key) {
                        let expires = await forge.readCertificateInfo(organization.host[i].cert);
                        expires = expires.notAfter;
                        if (this.isValid(expires)) {
                            this.setCertificate(host, expires, organization_id, hostKeyPath, organization.host[i].cert, organization.host[i].key)
                            return true
                        }
                    }
                    break
                }
            }

            if (!hostPosition && hostPosition !== 0)
                return false
        }

        return await this.requestCertificate(host, hostPosition, hostObject, organization_id, false)
    }

    async checkCertificate(host, organization_id, pathname = '') {
        let hostname = host.split(':')[0]
        if (hostname === 'localhost' || hostname === '127.0.0.1' || pathname.startsWith('/.well-known/acme-challenge/'))
            return true

        if (certificates[host]) {
            return true
        }

        const hostKeyPath = keyPath + host + '/';
        if (fs.existsSync(hostKeyPath + 'fullchain.pem')) {
            let cert = fs.readFileSync(hostKeyPath + 'fullchain.pem', 'utf8');
            let expires = await forge.readCertificateInfo(cert);
            expires = expires.notAfter;
            if (this.isValid(expires)) {
                this.setCertificate(host, expires, organization_id)
                return true
            }
        }

        if (!hosts[host])
            hosts[host] = this.getCertificate(host, organization_id)
        return hosts[host]
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

    setCertificate(host, expires, organization_id, hostKeyPath, cert, key) {
        // let expireDate = new Date(expires);
        // let currentDate = new Date();

        // Adjust the expireDate by the DAYS, HOURS, and MINUTES constants
        // expireDate.setDate(expireDate.getDate() - DAYS); // Subtracting to renew earlier
        // expireDate.setHours(expireDate.getHours() - HOURS);
        // expireDate.setMinutes(expireDate.getMinutes() - MINUTES);

        // Calculate the time difference in milliseconds
        // let timeoutDuration = expireDate.getTime() - currentDate.getTime();

        // Ensure we're not setting a negative timeout in case of past dates or errors
        // timeoutDuration = Math.max(timeoutDuration, 0);

        // Clear any existing timeout for the host
        // if (certificates[host] && certificates[host].timeout) {
        //     clearTimeout(certificates[host].timeout);
        // }

        // Set the timeout to call checkCertificate before the actual expiration
        // let timeout = setTimeout(() => {
        //     this.checkCertificate(host, organization_id);
        // }, timeoutDuration);

        // Store the timeout and organization_id for later reference or cancellation

        if (hostKeyPath) {
            if (!fs.existsSync(hostKeyPath)) {
                fs.mkdirSync(hostKeyPath, { recursive: true });
            }
            fs.writeFileSync(hostKeyPath + 'fullchain.pem', cert);
            // fs.chmodSync(keyPath + 'fullchain.pem', '444')
            fs.writeFileSync(hostKeyPath + 'private-key.pem', key);
            // fs.chmodSync(keyPath + 'private-key.pem', '400')
        }

        this.proxy.createServer(host)

        certificates[host] = { expires, organization_id }

    }

}

module.exports = CoCreateAcme;
