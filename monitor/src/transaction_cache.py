import os
import pickle
from typing import Dict, Any
from datetime import datetime
from cryptography.x509 import ReasonFlags


def read_binary_file(path_to_file: str) -> Any:
    try:
        with open(path_to_file, "rb") as fp:
            contents = pickle.load(fp)
    except FileNotFoundError as e:
        print(f'{e}')
        raise e

    return contents


def write_binary_file(path_to_file: str, contents: Any) -> bool:
    try:
        with open(path_to_file, "wb") as fp:
            pickle.dump(contents, fp)
    except FileNotFoundError as e:
        print(f'{e}')
        raise e
    return True


class tx_merkle_info:
    """ A simple class to manage which block & the merkle proof
    """
    def __init__(self):
        self.block_hash: str = ""
        self.merkle_proof: str = ""
        self.merkle_root: str = ""

    def __repr__(self):
        return f'block_hash: {self.block_hash} merkle_proof: {self.merkle_proof} merkle_root: {self.merkle_root}'


class IssuedCertificates:
    """ A class to manage issued certificate information
    """
    def __init__(self, cert_txid: str, cert_txindex: int, cert_tx_link: str):
        self.cert_txid = cert_txid
        self.cert_txindex = cert_txindex
        self.cert_tx_link = cert_tx_link
        self.block_info: tx_merkle_info = tx_merkle_info()

    def __repr__(self):
        return f'cert_tx_id: {self.cert_txid}\ncert_tx_index: {self.cert_txindex}\ncert_tx_link: {self.cert_tx_link}\nblock_hash: {self.block_info.block_hash}'


class ExpiredCertificate:
    """ A class to manage revoked certificate information
    """
    def __init__(self, cert_txid: str, cert_txindex: int, revoke_time: datetime, revoke_reason: ReasonFlags, spending_tx: str, default_block_browser: str):
        self.cert_txid: str = cert_txid
        self.cert_txindex: int = cert_txindex
        self.cert_txid_link: str = f'{default_block_browser}/tx/{cert_txid}'
        self.revoke_time: datetime = revoke_time
        self.revoke_reason: ReasonFlags = revoke_reason
        self.spending_txid = spending_tx
        self.spending_txid_link: str = f'{default_block_browser}/tx/{spending_tx}'
        self.block_info: tx_merkle_info = tx_merkle_info()

    def __repr__(self):
        return f'cert_tx_id: {self.cert_txid}\ncert_tx_index: {self.cert_txindex}\nspending_tx: {self.spending_txid}'


class TxCache:
    def __init__(self):
        self.tx_cache_expired_certs: Dict[int, ExpiredCertificate] = {}
        self.tx_cache_current_cert: Dict[int, IssuedCertificates] = {}
        self.path_to_tx_cache_files: str = ""
        self.default_block_browser: str = ""

    def __repr__(self) -> str:

        return_str = "Expired Certificate TX outputs\n"
        for k in self.tx_cache_expired_certs.keys():
            return_str += "{}:{}".format(k, self.tx_cache_expired_certs[k])

        return_str += "\nCurrent Certificate TX ouputs\n"
        for k in self.tx_cache_current_cert.keys():
            return_str += "{}:{}".format(k, self.tx_cache_current_cert[k])

        return return_str

    def set_config(self, config):
        self.path_to_tx_cache_files = config["path_to_tx_files"]
        self.default_block_browser = config["default_block_browser"]
        current_certs_file = os.path.join(self.path_to_tx_cache_files, "current_certs.dat")
        print(f'Checking for cache file {current_certs_file}')
        if os.path.isfile(current_certs_file):
            self.tx_cache_current_cert = read_binary_file(current_certs_file)

        expired_certs_file = os.path.join(self.path_to_tx_cache_files, "expired_certs.dat")
        print(f'checking for expired certs file {expired_certs_file}')
        if os.path.isfile(expired_certs_file):
            self.tx_cache_expired_certs = read_binary_file(expired_certs_file)

    """ if a tx with a certificate attached is not yet mined, return the serial number of the certificate & the tx_id
    """
    def lookup_tx_without_merkle_proofs(self) -> Dict[str, int]:
        issued_tx_list = {}
        for key in self.tx_cache_current_cert.keys():
            if self.tx_cache_current_cert[key].block_info.block_hash == "":
                issued_tx_list[self.tx_cache_current_cert[key].cert_txid] = key
        return issued_tx_list

    """ add block & merkle tree info to the certificate.
    """
    def update_tx_cert_merkle_info(self, serial_number: int, block_hash: str, merkle_root: str, merkle_proof: str) -> None:
        if serial_number not in self.tx_cache_current_cert.keys():
            raise ValueError('No entry for cert with serial number {serial_number} in current certificate cache')

        self.tx_cache_current_cert[serial_number].block_info.block_hash = block_hash
        self.tx_cache_current_cert[serial_number].block_info.merkle_root = merkle_root
        self.tx_cache_current_cert[serial_number].block_info.merkle_proof = merkle_proof

    def lookup_cert_tx(self, key: int) -> IssuedCertificates:
        if key not in self.tx_cache_current_cert:
            # print(f'key -> {key}\nCurrent certificates -> {self.tx_cache_current_cert}')
            raise ValueError(f'No Certificate found...{key}')

        return self.tx_cache_current_cert[key]

    """ True -> if the certificate is active
        False -> if the certificate is revoked
        exception if the cert serial number has not been seen
    """
    def cert_status(self, key: int) -> bool:
        if key not in self.tx_cache_current_cert and key not in self.tx_cache_expired_certs:
            raise ValueError(f'No certificate key found ... {key:X}')

        key_found = False
        if key in self.tx_cache_current_cert:
            # print(f'Certificate with id {key} still in tx_cache-current')
            key_found = True
        if key in self.tx_cache_expired_certs:
            key_found = False
        return key_found

    def look_up_revoked_tx(self, key: int) -> ExpiredCertificate:
        if key not in self.tx_cache_expired_certs:
            # print(f'Key -> {key} not part of the revoked list -> {self.tx_cache_expired_certs}')
            raise ValueError(f'No Revoked certificates found for key .. {key}')
        return self.tx_cache_expired_certs[key]

    def add_cert_tx(self, key: int, txid: str, tx_index: int) -> None:
        # print(f" add_cert_tx, key={key}, key-hex={hex(key)}, txid={txid}, tx_index={tx_index}")
        # check the current map.
        # if empty, add to the current map only
        # if the key exists then we have a problem
        hyperlink_format = f'{self.default_block_browser}/tx/{txid}'
        if key not in self.tx_cache_current_cert:
            self.tx_cache_current_cert[key] = IssuedCertificates(txid, tx_index, hyperlink_format)
        else:
            tx_info = self.tx_cache_current_cert[key]
            self.tx_cache_expired_certs[key] = ExpiredCertificate(tx_info.cert_txid, tx_info.cert_txindex, datetime.now(), ReasonFlags.unspecified, "", self.default_block_browser)
            # update the current_certs map
            self.tx_cache_current_cert[key] = IssuedCertificates(txid, tx_index, hyperlink_format)

        # sort out the path
        # dumps all the cache every time. Not great but it'll do for now
        self.write_to_files(self.path_to_tx_cache_files)

    def revoke_cert_tx(self, key: int, tx_id: str) -> None:
        print(f'revoking certificate transaction with key -> {key}')
        if key in self.tx_cache_current_cert:
            tx_info = self.tx_cache_current_cert[key]
            self.tx_cache_expired_certs[key] = ExpiredCertificate(tx_info.cert_txid, tx_info.cert_txindex, datetime.now(), ReasonFlags.unspecified, tx_id, self.default_block_browser)
            # remove from the current certificate cache
            del self.tx_cache_current_cert[key]
        else:
            print(f'revoke_cert_tx key not found-> {key}')

        self.write_to_files(self.path_to_tx_cache_files)

    # takes a file path, writes two files
    # current_certs.dat & expired_certs.dat
    def write_to_files(self, path: str) -> bool:
        path_to_file = os.path.join(path, "current_certs.dat")
        if not write_binary_file(path_to_file, self.tx_cache_current_cert):
            return False

        path_to_file = os.path.join(path, "expired_certs.dat")
        if not write_binary_file(path_to_file, self.tx_cache_expired_certs):
            return False
        return True

    # takes a file path & loads the TXCache data
    def read_from_files(self, path: str) -> bool:
        try:
            path_to_file = os.path.join(path, "current_certs.dat")
            self.tx_cache_current_cert = read_binary_file(path_to_file)
            path_to_file = os.path.join(path, "expired_certs.dat")
            self.tx_cache_expired_certs = read_binary_file(path_to_file)

        except FileNotFoundError as e:
            print(f'{e}')
            return False

        return True


tx_cache = TxCache()
