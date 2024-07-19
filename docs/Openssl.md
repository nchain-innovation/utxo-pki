# Openssl Commands
These are openssl commands that maybe useful in development:

# Certificates and CSR

## Read CSR subject
```bash
openssl req -in my.req -noout -subject
subject=C = UK, ST = Greater London, L = London, O = nChain, OU = Research, CN = my-server
```

## Import request into CA and sign
This is the operation that occurs inside the CA when a CSR is processed
```bash
cd easy-rsa
./easyrsa import-req ../practice-csr/my.req my-server
yes "yes"| ./easyrsa sign-req server my-server
```

## Create cert in pem format
```bash
openssl x509 -in ca.crt -outform PEM -out ca.pem
```

# OCSP 
## OCSP Responder 
Openssl can act as an OCSP responder, for example:
```bash
openssl ocsp -index index.txt -port 8888 -rsigner certs_by_serial/E0A768C73DB9876A89C18695318AE7CB.pem -rkey private/'OCSP Responder R1.key' -CA ca.pem -text -out log.txt
```
## Send OCSP Request
The following sends an OCSP request for the certificate with the serial number to the openssl OCSP Responder

```bash
openssl ocsp -issuer ca.pem -CAfile ca.crt -cert certs_by_serial/EF3BF98430FBCE0FBDF5DA7960C88400.pem -url http://127.0.0.1:8888 -resp_text -respout resp.der
```
and revoked
```bash
openssl ocsp -issuer ca.pem -CAfile ca.crt -cert revoked/certs_by_serial/6E5C48DA623787AFE00578E981C42409.crt -url http://127.0.0.1:8888 -resp_text -respout resp.der
```