#!/usr/bin/python3

from typing import MutableMapping, Any
import uvicorn
import sys
import os

sys.path.append('./tx-engine')

from framework import framework, FrameworkEvent
from cert_logic import on_certificate_status_change
from block_logic import sv_status
from tx_engine.interface.blockchain_interface import *
from tx_engine.interface.interface_factory import *

from certificate_authority import certificate_authority
from ocsp_responder import ocsp_responder
from transaction_actions import utxo_set
from transaction_cache import tx_cache
from funding_service import get_financing_service_status, get_balance
from util import load_config


def run_webserver(config: MutableMapping[str, Any]):
    """ Given the config run the webserver
    """
    address = config["address"]
    (host, port) = address.split(":")

    if os.environ.get("APP_ENV") == "docker":
        print("Running in Docker")
        # Allow all access in docker
        # (required as otherwise the localmachine can not access the webserver)
        host = "0.0.0.0"
    else:
        print("Running in native OS")
        # Only allow access from localmachine
        host = '127.0.0.1'

    # Run as HTTP
    uvicorn.run(
        "rest_api:app",
        host=host,
        port=int(port),
        log_level=config["log_level"],
        reload=config["reload"],
        workers=1,  # Don't change this number unless you understand the full implications of having shared data.
    )


def main():
    """ main function - reads config, sets up system starts REST API
    """
    config = load_config("../data/monitor.toml")

    # Setup certificate authority
    certificate_authority.set_config(config["certificate_authority"])

    # Setup ocsp_responder
    ocsp_responder.set_config(config["ocsp_responder"])

    # Setup bsv client
    bsv_client = interface_factory.set_config(config["bsv_client"])
    framework.set_bsv_client(bsv_client)

    # set up the tx_cache
    tx_cache.set_config(config["tx_cache_files"])

    # Setup the utxo_interface
    utxo_set.set_config(config["cert_wallets"])
    utxo_set.set_bsv_client(bsv_client)
    utxo_set.set_uaas_endpoint(config["uaas_interface"])

    # Ping the financing service, check we have a balace
    finance_srv = config["financing_service"]
    get_financing_service_status(finance_srv)
    balance = get_balance(finance_srv)
    if balance < 100000:
        print(f'Balance too low, please fund the address {finance_srv["client_id"]} with some satoshi')
        sys.exit(1)

    # Initial load the funding utxos, this has to be updated regularly
    try:
        utxo_set.update_unspents(bsv_client)
    except Exception as e:
        print("Unable to connect to blockchain")
        print(e)
        sys.exit(1)

    # Register business logic with framework
    framework.register_callback(
        FrameworkEvent.ON_CERT_CHANGE, on_certificate_status_change)

    framework.register_bsv_callback(
        sv_status.has_new_block, sv_status.new_block_event)

    framework.register_periodic_bsv_callback(utxo_set.update_unspents)

    run_webserver(config["web_interface"])


if __name__ == "__main__":
    main()
