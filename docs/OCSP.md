
# OCSP Responder

As part of this project we have created an OCSP Responser, written in Python.

OCSP (Online Certificate Status Protocol) is a method of checking the revocation status of certificates. It is specified in RFC 6960, as well as other obsoleted RFCs.

The following diagram shows how the OCSP Responder is used in establishing a HTTPS session between a browser and a website:

![HTTPS_Session](diagrams/Https_session_setup.png)

## OCSP Requester
Note that we have a tool for performing OCSP requests in the `monitor/src/tools` directory. 

The `ocsp_requester` takes the serial number of the certificate that you are interested in as a command line parameter:
```bash
./ocsp_requester.py -sn 8F0DBE8CB75FFC86ACD82F21D16B63DD
```

## Openssl
There are additional openssl commands that maybe useful [here](Openssl.md)