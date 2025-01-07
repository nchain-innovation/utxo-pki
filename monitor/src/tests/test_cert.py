#!/usr/bin/python3
import sys
sys.path.append("..")

import unittest
import logging

from tx_engine.interface import mock_interface
from cert_logic import on_certificate_status_change


class CertificateProcessingTests(unittest.TestCase):
    """ Tests of the on_certificate_status_change business logic
    """

    def test_cert_buslogic(self):
        # list with example valid and revoked certificates
        CERTS = ['V\t240919143429Z\t\t485502E94E6A9B4257BD61E472E99116\tunknown\t'
                 '/C=UK/ST=Greater London/L=London/O=nChain/OU=Research/CN=my-server\n',
                 'R\t240919144525Z\t211007132632Z\t5DB09A0A7E6205058D81A1227F604A22\tunknown\t'
                 '/C=UK/ST=Greater London/L=London/O=nChain/OU=Research/CN=my-server\n']

        bsv_client = mock_interface.MockInterface()
        on_certificate_status_change(CERTS, bsv_client)


if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    unittest.main()
