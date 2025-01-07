from fastapi import FastAPI, File, UploadFile, Request, Response
from fastapi.responses import FileResponse
from fastapi_utils.tasks import repeat_every
from typing import Any, MutableMapping, Dict
from framework import framework
from util import load_config, remove_path_and_extension
from cert_status_logic import is_valid_cert_file

from certificate_authority import certificate_authority

from ocsp_responder import ocsp_responder
# from blockchain_setup import blockchain_setup, is_ms_node
from transaction_actions import utxo_set, create_certificate_transaction, revoke_certifcate_transaction, revoke_certificate_impl

from transaction_cache import tx_cache
from cryptography.x509 import OID_COMMON_NAME

import os.path

tags_metadata = [
    {
        "name": "CA Monitor",
        "description": "CA Monitor Service Interface.",
    },
]


app = FastAPI(
    title="CA Monitor Service Interface",
    description="CA Monitor.",
    openapi_tags=tags_metadata,
)

config: MutableMapping[str, Any] = {}
web_address: str = ""


@app.on_event("startup")
def startup():
    """When the application starts read the config
    configure bsv_client
    """
    global config, web_address

    config = load_config("../data/monitor.toml")
    web_address = config["web_interface"]["address"]


@app.get("/", tags=["Monitor"])
def root() -> Dict[str, str]:
    """Get Monitor Root"""
    return {
        "name": "Monitor Service",
        "description": "CA Monitor Service Interface.",
    }


@app.on_event("startup")
@repeat_every(seconds=15)
def periodic_event() -> None:
    """ This function calls the event monitoring framework on
        startup and then every 15s thereafter.
    """
    framework.monitor()


# These are the Gets
@app.get("/issued", tags=["Status"])
def issued():
    """Return a list of issued certificates.
    """
    valid_serial_numbers = certificate_authority.get_list_of_valid_serial_numbers()
    return_dict = {}
    for items in valid_serial_numbers:
        try:
            issued_tx = tx_cache.lookup_cert_tx(items[0])
            # ensure the tx is in the utxo set
            utxo_info = utxo_set.get_tx_out_point(issued_tx.cert_txid, issued_tx.cert_txindex)
            if utxo_info is not None:
                certificate_info = {"Certificate subject": items[1],
                                    "Transaction ID": issued_tx.cert_txid,
                                    "Transaction Index": issued_tx.cert_txindex,
                                    "Transaction link": issued_tx.cert_tx_link,
                                    "block_hash": issued_tx.block_info.block_hash,
                                    "merkle_proof": issued_tx.block_info.merkle_proof,
                                    "merkle_root": issued_tx.block_info.merkle_root
                                    }
                return_dict[f'{items[0]:X}'] = certificate_info
            else:
                print(f'No UTXO FOund for output {issued_tx.cert_txid}:{issued_tx.cert_txindex}')
        except ValueError as err:
            print(f'No tx id found for valid serial number {items[0]} {err.__str__}')

    return return_dict


@app.get("/revoked", tags=["Status"])
def get_revoked():
    """Return a list of issued certificates.
    """
    serial_numbers = certificate_authority.get_list_of_revoked_serial_numbers()
    return_dict = {}
    for items in serial_numbers:
        try:
            tx_item = tx_cache.look_up_revoked_tx(items[0])
            certificate_info = {"Certificate subject": items[1],
                                "Certificate Transaction ID": tx_item.cert_txid,
                                "Certificate Transaction Index": tx_item.cert_txindex,
                                "Certificate Transaction Link": tx_item.cert_txid_link,
                                "Spending Transaction": tx_item.spending_txid,
                                "Spending Transaction Link": tx_item.spending_txid_link
                                }
            return_dict[f'{items[0]:X}'] = certificate_info
        except ValueError as err:
            print(f'No tx id found for valid serial number {items[0]} {err.__str__}')

    return return_dict


@app.get("/log", tags=["Status"])
def log():
    """ Get log of certificate events
    """
    return {
        "logs": certificate_authority.get_certificate_logs()
    }


@app.get("/cert_status", tags=["Status"])
def cert_status(name: str):
    """ Given a certificate name return the status of the
        certificate as a dictionary.
    """
    if certificate_authority.certificate_exists(name):
        cert = certificate_authority.get_cert_from_name(name)
        assert cert is not None
        try:
            if tx_cache.cert_status(cert.serial_number):
                cert_info = tx_cache.lookup_cert_tx(cert.serial_number)
                utxo_info = utxo_set.get_tx_out_point(cert_info.cert_txid, cert_info.cert_txindex)
                if utxo_info is not None:
                    certificate_info = {"Certificate Serial Number": f'{cert.serial_number:X}',
                                        "Certificate subject": cert.subject.rfc4514_string(),
                                        "Transaction ID": cert_info.cert_txid,
                                        "Transaction Index": cert_info.cert_txindex,
                                        "Transaction link": cert_info.cert_tx_link
                                        }
                    return {"status": certificate_info}
            else:
                expired_cert_info = tx_cache.look_up_revoked_tx(cert.serial_number)
                certificate_info = {"Certificate Serial Number": f'{cert.serial_number:X}',
                                    "Certificate subject": cert.subject.rfc4514_string(),
                                    "Transaction ID": expired_cert_info.cert_txid,
                                    "Transaction Index": expired_cert_info.cert_txindex,
                                    "Transaction link": expired_cert_info.cert_txid_link,
                                    "Spending Transaction link": expired_cert_info.spending_txid_link
                                    }
                return {"status": certificate_info}

        except ValueError as err:
            print(f'Error -> {err}')
            return {"status": err.__repr__()}
    else:
        return {
            "status": f"Error: Unable to find certificate '{name}'."
        }


@app.get("/cert_file", tags=["File"])
def cert_file(name: str):
    """ Given a certificate name return the certificate file.
    """
    return certificate_authority.get_cert_file(name)


@app.get("/key_file", tags=["File"])
def key_file(name: str):
    """ Given a name return the associated key file.
    """
    return certificate_authority.get_key_file(name)


@app.get("/ca_cert", tags=["File"])
def ca_cert():
    """Return the CA's public key cert.
    """
    return certificate_authority.get_ca_cert()


# These are the POSTs
@app.post("/utxo test status", tags=["Status"])
def verify_utxo(txid: str, tx_index: int):
    utxo_info = utxo_set.get_tx_out_point(txid, tx_index)
    print(f'utxo info -> {utxo_info}')
    return {"Status": "Success"}


@app.post("/cert_file_status", tags=["Status"])
def cert_file_status(file: UploadFile = File(...)):
    """ Given a certificate file return the  status of the
        certificate as a dictionary.
    """
    return is_valid_cert_file(file)


@app.post("/create_cert", tags=["Create"])
def create_cert(name: str):
    """ Given a name create a certificate and return certificate file
    """
    if not certificate_authority.certificate_exists(name):

        finance_srv = config["financing_service"]
        cert_file_name = certificate_authority.create_certificate(name)
        create_certificate_transaction(cert_file_name, utxo_set, finance_srv)

        # Return the certificate file
        file_name = os.path.split(cert_file_name)[-1]
        return FileResponse(path=cert_file_name, filename=file_name, media_type="text")
    else:
        return {
            "status": f"Error: Certificate '{name}' already exists."
        }


@app.post("/sign_csr", tags=["Create"])
def sign_csr(file: UploadFile = File(...)):
    """ Given a CSR file sign it and return certificate file
    """
    contents = file.file.read()
    print(f"file.filename = {file.filename}")
    cert_file_name = certificate_authority.sign_csr(file.filename, contents)
    finance_srv = config["financing_service"]
    create_certificate_transaction(cert_file_name, utxo_set, finance_srv)
    # Return the certificate file
    file_name = os.path.split(cert_file_name)[-1]
    return FileResponse(path=cert_file_name, filename=file_name, media_type="text")


@app.post("/revoke_cert_file", tags=["Revoke"])
def revoke_cert_file(file: UploadFile = File(...)):
    """ Given a certificate file revoke it.
    """
    finance_srv = config["financing_service"]
    cert_name = remove_path_and_extension(file.filename)
    if certificate_authority.certificate_exists(cert_name):
        if not revoke_certifcate_transaction(file, utxo_set, finance_srv):
            return {"status": f'Unable to remove certificate from the UTXO {cert_name}'}
        return certificate_authority.revoke_certificate_file(file)
    else:
        return {
            "status": f"Error: Unable to find certificate '{cert_name}'."
        }


@app.post("/revoke_cert", tags=["Revoke"])
def revoke_cert(name: str):
    """ Given a name revoke a certificate

    """
    finance_srv = config["financing_service"]
    if certificate_authority.certificate_exists(name):
        cert = certificate_authority.get_cert_from_name(name)
        assert cert is not None
        if not revoke_certificate_impl(cert, utxo_set, finance_srv):
            return {"status": f'Unable to remove certificate from the UTXO {name}'}
        return certificate_authority.revoke_certificate(name)
    else:
        return {
            "status": f"Error: Unable to find certificate '{name}'."
        }


@app.post("/revoke_cert_by_serial_number", tags=["Revoke"])
def revoke_cert_serial_number(serial_num: str):
    """ Given a certificate serial number, revoke it (spending the UTXO)
    """

    cert = certificate_authority.get_cert_from_serial_number(serial_num)
    if cert is None:
        return {"status": f"Error: Unable to find certificate from serial number -> {serial_num}"}

    cert_attribs = cert.subject.get_attributes_for_oid(OID_COMMON_NAME)
    cert_file_name: str = ""
    if cert_attribs:
        if isinstance(cert_attribs[0].value, bytes):
            cert_file_name = cert_attribs[0].value.decode('utf-8').strip()
        else:
            cert_file_name = cert_attribs[0].value.strip()
    else:
        return {
            "status": f"Error: No Common Name attached to cerificate id {serial_num}."
        }

    # get the CN part of the
    # cert_file_name = cert.subject.get_attributes_for_oid(OID_COMMON_NAME)[0].value.strip()
    # print(f'Revoking certificate with file name -> {cert_file_name}')
    # print(f"Revoking certificate with file name -> {cert_file_name.decode('utf-8') if isinstance(cert_file_name, bytes) else cert_file_name}")
    if certificate_authority.certificate_exists(cert_file_name):
        if not revoke_certificate_impl(cert, utxo_set, finance_srv=config["financing_service"]):
            return {"status": f'Unable to remove certificate from the UTXO {cert_file_name}'}
        return certificate_authority.revoke_certificate(cert_file_name)
    else:
        return {
            "status": f"Error: Unable to find certificate {cert_file_name}."
        }


@app.post("/ocsp", tags=["OCSP"])
async def ocsp(request: Request) -> Response:
    """ OCSP Responder
        Query endpoint with:
        openssl ocsp -issuer ca.pem -cert certs_by_serial/EF3BF98430FBCE0FBDF5DA7960C88400.pem -url http://localhost:5003/ocsp -resp_text -respout resp.der
    """
    der_ocsp_req = await request.body()
    data = ocsp_responder.handle_request(der_ocsp_req)
    if data is not None:
        return Response(content=data, media_type="application/ocsp-response")
    else:
        return Response(content=None, media_type="application/ocsp-response")


def create_cert_files(keyfile: str, certfile: str, cert_type: str) -> None:
    """ Given keyfile and certfile create certifcate
    """
    subject = remove_path_and_extension(keyfile)
    certificate_authority.create_cert(subject, keyfile, certfile, cert_type)


@app.post("/setup_ca", tags=["Admin"])
def setup_ca(ca_name: str):
    """ Create a new certificate authority with the given CA name.
    """
    global config

    # Setup the CA
    retval = certificate_authority.setup_ca(ca_name)

    # Create the certs required for OCSP responder
    try:
        create_cert_files(
            config["ocsp_responder"]["responder_keyfile"],
            config["ocsp_responder"]["responder_certfile"],
            "ocsp")
    except KeyError as e:
        print(e)

    return retval


@app.post("/setup_blockchain", tags=["Admin"])
def setup_blockchain():
    """ Sets up accounts and credit for on blockchain ready for demonstration.
        This functionality is now supplied by Satoshi-labs.
    """
    return {
        "result": "failed",
        "reason": "Not supported"
    }


'''
@app.post("/setup_blockchain", tags=["Admin"])
def setup_blockchain():
    """ Sets up accounts and credit for on blockchain ready for demonstration.
        Note that this works for the ms-node blockchain.
    """
    global config
    # Read config and check that we are connected to correct blockchain

    if not is_ms_node(config["bsv_client"]):
        return {
            "result": "failed",
            "reason": "Not connected to ms-node"
        }

    bsv_client = framework.get_bsv_client()
    if not isinstance(bsv_client, BSVClientInSandbox):
        return {
            "result": "failed",
            "reason": "Incorrect bsv_client"
        }

    return blockchain_setup(config, bsv_client)
'''
