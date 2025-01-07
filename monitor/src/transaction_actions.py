import logging
from typing import Dict, List, Union, MutableMapping, Any
import requests
from fastapi import UploadFile

import json

from tx_engine import Tx, TxIn, TxOut
from tx_engine import Wallet, p2pkh_script, address_to_public_key_hash
from tx_engine import Script
from tx_engine.engine.op_codes import OP_DROP
from tx_engine.interface.blockchain_interface import BlockchainInterface

from transaction_cache import tx_cache
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from funding_service import fund_transaction

LOGGER = logging.getLogger(__name__)

'''
def text_to_dict(inputstr: str) -> Dict[str, Any]:
    inputstr = inputstr.replace("{", "").replace("}", "").split(",")
    dictionary: dict = {}
    for i in inputstr:
        dictionary[i.split(":")[0].strip('\'').replace("\"", "")] = i.split(":")[1].strip('"\'')
    return dictionary
'''

""" transaction & utxo monitoring actions in python
"""


class UTXOSet:
    def __init__(self):
        self.funding_key: Wallet
        self.certificate_key: Wallet

        # a randomly choosen amount to assign to a tx certificate(configurable)
        self.certificate_tx_amount: int
        # a default fee for p2pkh transactions (configurable)
        self.default_p2pkh_fee: int
        # unspent_outputs is used to create new certificate entries
        self.unspent_outputs: List[Dict] = []

        # SV connection details
        self.bsv_client: BlockchainInterface

        # utxo service end-point
        self.uaas_endpoint: str

        # utxo collection to lookup in the utxo service
        self.collection: str

    def __repr__(self):
        represented_unspent_dict = []
        for entry in self.unspent_outputs:
            for k, v in entry.items():
                represented_unspent_dict.append("{0}: {1}".format(k, v))

        return "{" + ", ".join(represented_unspent_dict) + "}"

    def set_config(self, config):
        self.funding_key = Wallet(config["funding_key"])
        self.certificate_key = Wallet(config["certificate_key"])
        self.certificate_tx_amount = config["certificate_value"]
        self.default_p2pkh_fee = config["default_p2pkh_fee"]

    def set_uaas_endpoint(self, config) -> None:
        self.uaas_endpoint = config["address"]
        self.collection = config["uaas_collection"]

    def fund_account_balance(self) -> int:
        value = self.bsv_client.get_balance(self.funding_key.get_address())
        print(f'balance for -> {self.funding_key.get_address()} = {value}')
        return value

    def set_bsv_client(self, client: BlockchainInterface) -> None:
        self.bsv_client = client

    # this seems odd & a bit weird. It takes a parameter & then does nothing with it?
    def update_unspents(self, bsv_client: BlockchainInterface):
        self.unspent_outputs = self.bsv_client.get_utxo(self.funding_key.get_address())

    def get_funding_unspents(self):
        return self.unspent_outputs

    def get_cert_public_addr(self) -> str:
        return self.certificate_key.get_address()

    def get_funding_public_addr(self) -> str:
        return self.funding_key.get_address()

    def get_utxo_client(self) -> BlockchainInterface:
        return self.bsv_client

    def get_certificate_tx_amount(self) -> int:
        return self.certificate_tx_amount

    def get_default_p2pkh_fee(self) -> int:
        return self.default_p2pkh_fee

    def get_tx_out_point(self, txid: str, txindex: int) -> Dict:
        headers = {'content-type': 'application/json'}
        url: str = self.uaas_endpoint + "/tx/utxo_by_outpoint"
        params: Dict[str, Union[str, int]] = {'hash': txid, 'pos': txindex}

        r = requests.get(url, params=params, headers=headers)
        if r.status_code == 200:
            r_success = json.loads(r.text)
            if not r_success["result"]:
                print(f'Error checking uxto status for outpoint {txid}/{txindex}')
                return {}

            url_tx: str = self.uaas_endpoint + "/collection/tx/raw"
            params_tx = {'cname': self.collection, 'hash': txid}
            r_tx = requests.get(url_tx, params=params_tx, headers=headers)
            if r_tx.status_code == 200:
                json_tx_val = json.loads(r_tx.text)
                tx: Tx = Tx.parse(bytes.fromhex(json_tx_val["result"]))
                return_dict: dict = {}
                return_dict["Amount"] = tx.tx_outs[txindex].amount
                return_dict["scriptPubKey"] = tx.tx_outs[txindex].script_pubkey
                return_dict["tx"] = tx
                return return_dict
            else:
                print(f'Error downloading the transaction from the uaas {txid}/{txindex} with error {r_tx.status_code}')
                return {}

        else:
            print(f'Error checking uxto status CURL request to the UAAS {r.status_code}')
            return {}


# Given a transaction, broadcast it to the network
def broadcast_tx(utxo: UTXOSet, tx: Tx) -> bool:

    try:
        response = utxo.bsv_client.broadcast_tx(tx.serialize().hex())

        if response.status_code == 200:
            # print(response.content)
            return True
        elif response.status_code == 500:
            print("ERROR - status code is 500")
            print(f'{response.content}')
            raise RuntimeError("500 error")
        else:
            print("UNKNOWN ERROR")
            print(f'{response.content}')
            raise RuntimeError("broadcast_tx failed")
    except Exception as error:
        print(f"broadcast_tx: error = {error}")
        raise RuntimeError("broadcast_tx failed")


# Calculate the actual fee:
#  - this needs includes the 1000 sats for the certificate
#  - the fee estimate for the payload
#  - a default fee I'm calling "Murphy's fudge factor" (as sometime our transactions were not getting mined)
def calculate_fee(payload_length: int, utxo: UTXOSet) -> int:

    # Cost for BSV tx is 500 sats/1000 bytes, According to WoC MAPI.
    #  - Calculate the fee estimate for the payload
    fee_estimate = int((payload_length / 1000) * 500)
    print(f'length of data {payload_length}\nfee estimate -> {fee_estimate}')

    adjusted_estimate = utxo_set.get_certificate_tx_amount() + fee_estimate + utxo.get_default_p2pkh_fee()
    print(f'adjusted_estimate -> {adjusted_estimate}')
    return adjusted_estimate


# Given a file name, create a utxo containing the certificate
def create_certificate_transaction(cert_file_name: str, utxo: UTXOSet, finance_srv: MutableMapping[str, Any]) -> None:

    with open(cert_file_name, "r") as f:
        cert_buf = f.read()

    cert = x509.load_pem_x509_certificate(cert_buf.encode())

    payload = {'cert_id': cert.serial_number,
               'cert_sub': cert.subject.rfc4514_string(),
               'cert': cert.public_bytes(Encoding.PEM).decode("utf-8")}

    json_payload = json.dumps(payload)

    # calculate the fee for the certificate transaction
    fee = calculate_fee(len(json_payload.encode()), utxo)

    # Create a locking script for the funding transaction
    funding_locking_script = p2pkh_script(address_to_public_key_hash(utxo.get_funding_public_addr()))
    # print(funding_locking_script.print_script())

    # Create a locking script for the certificate transaction
    data_payload_script: Script = Script()
    data_payload_script.append_pushdata(json_payload.encode())
    data_payload_script.append_byte(OP_DROP)
    certificate_locking_script = data_payload_script + p2pkh_script(address_to_public_key_hash(utxo.get_cert_public_addr()))

    # fund the transaction
    spendable_outpoints_tx = fund_transaction(finance_srv, fee, funding_locking_script)
    # print(f'spendable_outpoints -> {spendable_outpoints}')

    # create the certificate transaction outpoints
    vouts = []
    vouts.append(TxOut(amount=utxo.get_certificate_tx_amount(), script_pubkey=certificate_locking_script.get_commands()))
    # print(vouts)

    # create the certificate transaction inputs
    vins = []
    for outs in spendable_outpoints_tx["outpoints"]:
        vins.append(TxIn(prev_tx=outs["hash"], prev_index=outs["index"]))
    print(f"vins = {vins}")

    input_tx: Tx = Tx.parse(bytes.fromhex(spendable_outpoints_tx["tx"]))
    tx = Tx(version=1,
            tx_ins=vins,
            tx_outs=vouts,
            locktime=0)

    # sign it
    # key info
    print(f'Before signing public key -> {utxo.funding_key.get_public_key_as_hexstr()}  private key -> {utxo.funding_key.to_wif()}')
    tmp_tx: Tx = tx.copy()
    for i in range(len(tx.tx_ins)):
        print(f'Signing loop -> i = {i}, input tx = {input_tx.id()}, tmp_tx = {tmp_tx.id()}, tx = {tx.id()}')
        signed_tx: Tx = utxo.funding_key.sign_tx(i, input_tx, tmp_tx)
        print(f'signing loop post sign -> signed_tx -> {signed_tx.id()}')
        tmp_tx = signed_tx.copy()
    print(f'tmp_tx after signing ended -> {tmp_tx.id()}')
    # send it
    print(tmp_tx.serialize().hex())
    print(f'After signing public key -> {utxo.funding_key.get_public_key_as_hexstr()}  private key -> {utxo.funding_key.to_wif()}')
    broadcast_tx(utxo, tmp_tx)

    # add the info to the cache
    tx_cache.add_cert_tx(cert.serial_number, tmp_tx.id(), 0)
    # update the utxo set
    # weirdly, update_unspents needs a parater that it also contains
    utxo_set.update_unspents(utxo.get_utxo_client())


def spend_certificate_transaction(tx_id: str, tx_index: int, cert_key: int, utxo: UTXOSet, finance_srv: MutableMapping[str, Any]) -> None:
    """ Given an input tx & index, create a tx that spends the utxo (funded by the funding wallet)
        The transaction caches are updated to reflect certificates being revoked
    """
    print("spend_certificate_transaction"
          f" tx_id -> {tx_id}\n"
          f" tx_index -> {tx_index}\n"
          f" cert_key -> {cert_key}\n")

    # verify that the tx_id & index are in the actual utxo set
    tx_unspent = utxo.get_tx_out_point(tx_id, tx_index)
    if tx_unspent is None:
        raise ValueError(f"spend_certificate_transaction -> No UTXO available for tx id  {tx_id} tx_index {tx_index}")

    # basic check that the scriptPubKey has an entry
    assert tx_unspent["scriptPubKey"] is not None
    print('Tx verified in the UTXO set')

    # calculate the fee for the revocation transaction
    fee = utxo.get_default_p2pkh_fee()

    # create the locking script for the funding transaction
    funding_locking_script = p2pkh_script(address_to_public_key_hash(utxo.get_funding_public_addr()))

    # fund the transaction
    spendable_outpoints = fund_transaction(finance_srv, fee, funding_locking_script)
    print(f'spendable_outpoints -> {spendable_outpoints}')

    assert tx_unspent["tx"] is not None
    print(f'certificate tx -> {tx_unspent["tx"].serialize().hex()}')
    # create the certificate transaction outpoints
    vouts = []
    vouts.append(TxOut(amount=utxo.get_certificate_tx_amount(), script_pubkey=funding_locking_script.get_commands()))

    # create the certificate transaction inputs
    vins = []
    # append the certificate outpoint

    vins.append(TxIn(prev_tx=tx_id, prev_index=tx_index, script=b'', sequence=0xFFFFFFFF))
    # append the spendable outpoints from funding service
    for outpoint in spendable_outpoints["outpoints"]:
        vins.append(TxIn(prev_tx=outpoint["hash"], prev_index=outpoint["index"], script=b'', sequence=0xFFFFFFFF))

    tx = Tx(version=1,
            tx_ins=vins,
            tx_outs=vouts,
            locktime=0)

    funding_input_tx: Tx = Tx.parse(bytes.fromhex(spendable_outpoints["tx"]))

    signed_tx: Tx = utxo.certificate_key.sign_tx(0, tx_unspent["tx"], tx)

    tmp_tx = signed_tx
    for i in range(1, len(tx.tx_ins)):
        signed_tx_tmp: Tx = utxo.funding_key.sign_tx(i, funding_input_tx, tmp_tx)
        tmp_tx = signed_tx_tmp

    # send it
    broadcast_tx(utxo, tmp_tx)
    # remove the info from the cache
    tx_cache.revoke_cert_tx(cert_key, tmp_tx.id())
    # update the utxo set
    utxo_set.update_unspents(utxo_set.get_utxo_client())


def validate_certificate_tx(cert_serial_number: int, utxo_set: UTXOSet) -> bool:
    """ based on a certificate serial number, this function looks up the utxo information
        tries to load the certifate & returns true if the requested serial number matches the
        serial number of the certificate at the UTXO
    """
    try:
        issued_tx = tx_cache.lookup_cert_tx(cert_serial_number)
    except ValueError as err:
        print(f'{err}')
        return False

    # to validate the transaction, check via the bitcoin utxo set (rpc command gettxout "txid" txindex)
    # we could add a second check to ensure the tx is valid also
    tx_out_dict = utxo_set.get_tx_out_point(issued_tx.cert_txid, issued_tx.cert_txindex)
    assert tx_out_dict['scriptPubKey'] is not None

    script_str: str = tx_out_dict['scriptPubKey'].script_pubkey.to_string()
    cert_hex: str = ""
    try:
        target_index = script_str.split().index('OP_DROP')
        if target_index != 0:
            cert_hex = script_str.split()[target_index - 1]
    except ValueError as e:
        raise RuntimeError(f'{e}')

    cert_info = json.loads(bytes.fromhex(cert_hex[2:]).decode())
    assert cert_info["cert_id"] == cert_serial_number

    # load the certificate
    cert = None
    cert = x509.load_pem_x509_certificate(cert_info["cert"].encode())
    if cert is None:
        print(f'certificate serial numner {cert_serial_number} could not be loaded')
        return False

    # some checks around validity for the times
    return True


def revoke_certificate_impl(cert: x509.Certificate, utxo_set: UTXOSet, finance_srv: MutableMapping[str, Any]) -> bool:
    try:
        issued_tx_info = tx_cache.lookup_cert_tx(cert.serial_number)
        print(f'revoke_certificate_impl tx info -> {issued_tx_info} ')
        spend_certificate_transaction(issued_tx_info.cert_txid, issued_tx_info.cert_txindex, cert.serial_number, utxo_set, finance_srv)
    except ValueError as err:
        print(f'{err}')
        return False

    return True


def revoke_certifcate_transaction(file: UploadFile, utxo_set: UTXOSet, finance_srv: MutableMapping[str, Any]) -> bool:
    """ Given a certificate UpLoadFile, spend the UTXO output returning the amount to the
        funding wallet
    """
    cert_buf = file.file.read()
    cert = x509.load_pem_x509_certificate(cert_buf)
    return revoke_certificate_impl(cert, utxo_set, finance_srv)


def get_cert_from_utxo(cert_serial_number: int, utxo_set: UTXOSet) -> x509.Certificate:
    """ Given a certificate serial number, return the certificate from the UTXO set
    """
    issued_tx_info = tx_cache.lookup_cert_tx(cert_serial_number)
    tx_out_dict = utxo_set.get_tx_out_point(issued_tx_info.cert_txid, issued_tx_info.cert_txindex)
    assert tx_out_dict["scriptPubKey"] is not None
    script_pubkey = tx_out_dict["scriptPubKey"]

    script_as_str: str = script_pubkey.to_string()
    split_script = script_as_str.split()
    cert_hex: str = ""
    try:
        target_index = split_script.index('OP_DROP')
        if target_index == 0:
            raise ValueError('OP_DROP IS AT THE BEGINNING OF THE SCRIPT')
        cert_hex = split_script[target_index - 1]
    except ValueError as e:
        raise ValueError(f'{e}')

    cert_decoded = bytes.fromhex(cert_hex[2:]).decode()
    cert_info = json.loads(cert_decoded)
    assert cert_info["cert_id"] == cert_serial_number

    # load the certificate
    cert = None
    cert = x509.load_pem_x509_certificate(cert_info["cert"].encode())
    assert cert is not None
    return cert


def load_tx(tx_id: str, utxo_set: UTXOSet) -> Tx:
    raw_tx_str = utxo_set.get_utxo_client().get_raw_transaction(tx_id)
    tx: Tx = Tx.parse(bytes.fromhex(raw_tx_str))
    assert tx is not None
    return tx


def get_cert_from_raw_tx(cert_serial_number: int, utxo_set: UTXOSet) -> x509.Certificate:
    """ Given a certificate serial number, return the certificate from the raw transaction
        This is required if the UTXO is spent and the certificate has been revoked
    """
    issued_tx = tx_cache.lookup_cert_tx(cert_serial_number)
    tx = load_tx(issued_tx.cert_txid, utxo_set)
    script_str: str = tx.tx_outs[issued_tx.cert_txindex].script_pubkey.to_string()
    cert_hex: str = ""
    try:
        target_index = script_str.split().index('OP_DROP')
        if target_index != 0:
            cert_hex = script_str.split()[target_index - 1]
    except ValueError as e:
        raise RuntimeError(f'{e}')

    cert_info = json.loads(bytes.fromhex(cert_hex[2:]).decode())
    cert = x509.load_pem_x509_certificate(cert_info["cert"].encode())
    return cert


def get_cert_from_tx_id(tx_id: str, tx_index: int, utxo_set: UTXOSet) -> x509.Certificate:
    tx = load_tx(tx_id, utxo_set)
    script_str: str = tx.tx_outs[tx_index].script_pubkey.to_string()
    cert_hex: str = ""
    try:
        target_index = script_str.split().index('OP_DROP')
        if target_index != 0:
            cert_hex = script_str.split()[target_index - 1]
    except ValueError as e:
        raise RuntimeError(f'{e}')

    cert_info = json.loads(bytes.fromhex(cert_hex[2:]).decode())
    cert = x509.load_pem_x509_certificate(cert_info["cert"].encode())
    return cert


utxo_set = UTXOSet()
