# Website Certificate Demonstration

This section describes the steps required to setup Firefox browser on MacOS to demonstrate UTXO-PKI.


<br /><br />
1) Setup Blockchain UTXO balances (this can be mainnet or testnet)
* Set up a private/public key pair for the funding activity
* Set up a private/public key pair for the certificate activity
* Ensure that both have some available satoshi available
* Please remember to add the private key information to the toml file in monitor/data/monitor.toml

<br /><br />
2) Setup CA
* Run the REST api endpoint at localhost:5003/docs
* Select the admin POST `setup_ca` endpoint
* Press `Try it out`
* Enter the `CA Name`
* Press `Execute`
* Check the response, note that you can also check the service logs
* Stop and restart the monitor service

<br /><br />
3) Set Firefox config
* Type `about:config` into the address bar, this will provide you access to the following settings
    * security.OCSP.require  - true
    * security.ssl.enable_ocsp_must_staple = false
    * security.ssl.enable_ocsp_stapling = false
    * set security.enterprise_roots.enabled - true

<br /><br />
4) Export Load CA certificate
* Export the CA certificate from REST api
* Select the admin GET `get_ca` endpoint
* Press `Try it out`
* Press `Execute`
* Select `Download file`


<br /><br />
5) Load CA into Firefox
* Open Firefox
* Go to menu `Settings` search for `certificates`
* `View Certificates` and `Import` and select the downloaded `ca.crt`
* Click `Trust this CA to indentify web sites` and click OK

<br /><br />
6) Restart Firefox for settings and certificate load to take effect.

<br /><br />
7) Generate the certificate for the target website
* Generate a `localhost.crt` and `localhost.key` using `camonitor` service
* Select POST `create_cert`
* Press `Try it out`
* Enter `localhost` as the certificate name
* Press `Execute`
* Download the certificate file

<br /><br />
8) Download the key file
* Select GET `key_file`
* Press `Try it out`
* Enter `localhost` as the key name
* Press `Execute`
* Download the key file

<br /><br />
9) Check the blockchain to find the transaction that creates the certificate UTXO

<br /><br />
10) Install certificates into target website
* Copy `localhost.crt` and `localhost.key` into website/src/certs
* Start website service `run.sh`

<br /><br />
11) Access the website with the Firefox browser
* Start Firefox
* The address is https://localhost:5005
* This should establish a secure session as seen from the `https` and certificate in the address bar.
* Firefox should also access the OCSP endpoint as can be seen from the `camonitor` service logs.

<br /><br />
12) Revoke the website certificate and

* From the REST api select POST `revoke_cert_file`
* Press `Try it out`
* Select the file to revoke (`localhost.crt`)
* Press `Execute`
* Check the blockchain to find the transaction that spends the certificate UTXO

<br /><br />
13) connect Firefox
* Stop Firefox
    * Note that Firefox caches OCSP responses, until restarted
* Start Firefox
* The address is https://localhost:5005
* Access the website, the secure session should fail with the error: `SEC_ERROR_REVOKED_CERTIFICATE`

* Note the browser will report `SEC_ERROR_OCSP_MALFORMED_RESPONSE` if the certificate is not found.

* Note the browser will report `SEC_ERROR_OCSP_INVALID_SIGNING_CERT` if the monitor service has not been restarted after a new CA is created.
As the OCSP response will be signed by a previous CA.
