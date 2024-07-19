from typing import Dict
import pprint
from fastapi import UploadFile

from cryptography import x509
from transaction_actions import validate_certificate_tx, utxo_set

pp = pprint.PrettyPrinter()


def is_valid_cert_file(file: UploadFile) -> Dict[str, str]:
    """ Given a certificate file return a dictionary providing info about certificate.
    """
    cert_buf = file.file.read()
    cert = x509.load_pem_x509_certificate(cert_buf)
    if cert is None:
        return {
            "file": f"filename = {file.filename}",
            "Status": "unable to load x509 certificate"
        }

    if cert is not None:
        # add sanity checks on the validity of the certificate
        # check in the tx_cache + blockchain for a valid utxo
        if not validate_certificate_tx(cert.serial_number, utxo_set):
            return{
                "file": f"{file.filename}",
                "Status": "Not valid from the UTXO"
            }
        return{
            "file": f"{file.filename}",
            "Status": "Valid"
        }
