from typing import List

from tx_engine.interface.blockchain_interface import BlockchainInterface


def on_certificate_status_change(certs: List[str], bsv_client: BlockchainInterface):
    """ Code called when the certificate status changes
    """
    print("on_certificate_status_change")

    """
    The index.txt is an ascii file consisting of four fields

    where:
    1 - V - Certificate is Valid (R for revoked certificates )
    2 - 0051213070133Z - Date upto which the certificate is valid
    3 - B3500880020644B6 - Serial number of the certificate
    4- /C=3DIN/ST=3DTamilNadu/O=3Dcbe/CN=3Dtest - subject of the certificate

    There are 3 possiblities here:
    1) new certificate is issues
    2) existing certificate is revoked
    3) existing certififcate is renewed

    list with example valid and example revoked certificates
    ['V\t240919143429Z\t\t485502E94E6A9B4257BD61E472E99116\tunknown\t'
    '/C=UK/ST=Greater London/L=London/O=nChain/OU=Research/CN=my-server\n',
    'R\t240919144525Z\t211007132632Z\t5DB09A0A7E6205058D81A1227F604A22\tunknown\t'
    '/C=UK/ST=Greater London/L=London/O=nChain/OU=Research/CN=my-server\n']

    Note that with this being polled periodically there is the opportunity
    for a certificate to be issued and revoked in one step
    """
    for cert in certs:
        c = list(cert.split("\t"))
        print(f"c = {c}")
