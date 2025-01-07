#!/usr/bin/python3
import sys
sys.path.append("..")

import unittest
import logging

from tx_engine.interface import mock_interface
from block_logic import sv_status


class BlockProcessingTests(unittest.TestCase):
    """ Tests of the sv_status business logic
    """

    def test_cert_buslogic(self):
        bsv_client = mock_interface.MockInterface()
        # Set up mock client as required
        bsv_client.block_count = 1234
        sv_status.new_block_event(bsv_client)


if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    unittest.main()
