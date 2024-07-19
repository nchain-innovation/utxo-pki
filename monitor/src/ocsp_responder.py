from typing import MutableMapping, Any, Optional
from cryptography.x509 import ocsp, Certificate
from cryptography.x509.ocsp import OCSPCertStatus
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from certificate_authority import certificate_authority
from transaction_actions import get_cert_from_utxo, get_cert_from_tx_id, utxo_set
from transaction_cache import tx_cache
import datetime

from util import load_cert_pem_file, load_key_pem_file


class OCSPResponder:
    """ Class to encapsulate the OCSP Responder functionality
        This will need to interact with the Cerificate Authority
    """
    def __init__(self):
        self.issuer_certfile: str
        self.responder_certfile: str
        self.responder_keyfile: str

        self.issuer_cert: Optional[Certificate]
        self.responder_cert: Optional[Certificate]
        # self.responder_key_pem

    def set_config(self, config: MutableMapping[str, Any]):
        self.issuer_certfile = config["issuer_certfile"]
        self.responder_certfile = config["responder_certfile"]
        self.responder_keyfile = config["responder_keyfile"]
        # Load CA
        self.issuer_cert = load_cert_pem_file(self.issuer_certfile)
        # Load responder cert & key
        self.responder_cert = load_cert_pem_file(self.responder_certfile)
        self.responder_key = load_key_pem_file(self.responder_keyfile)

    def _issued_cert(self, ocsp_req: ocsp.OCSPRequest) -> bool:
        """ Given the request returns true if we issued the cert
        """
        if self.issuer_cert is None:
            return False
        else:
            der_issuer = self.issuer_cert.issuer.public_bytes()
            digest = hashes.Hash(ocsp_req.hash_algorithm)
            digest.update(der_issuer)
            issuer_hash = digest.finalize()
            return ocsp_req.issuer_name_hash == issuer_hash

    def create_response(self, cert: Certificate, cert_status: OCSPCertStatus, revoke_time, revoke_reason, ocsp_req) -> bytes:
        assert isinstance(self.issuer_cert, Certificate)
        assert isinstance(self.responder_cert, Certificate)
        assert isinstance(self.responder_key, RSAPrivateKey)
        # Create the response
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert,
            issuer=self.issuer_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=datetime.datetime.now(),
            next_update=datetime.datetime.now(),
            revocation_time=revoke_time,
            revocation_reason=revoke_reason
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, self.responder_cert
        )
        builder = builder.certificates([self.responder_cert])
        # Set the nonce
        for e in ocsp_req.extensions:
            builder = builder.add_extension(e.value, e.critical)

        # Sign the response
        response = builder.sign(self.responder_key, hashes.SHA256())
        return response.public_bytes(Encoding.DER)

    def handle_request(self, der_ocsp_req: bytes) -> Optional[bytes]:
        """ Handle OCSP Request
            openssl ocsp -issuer ca.pem -cert certs_by_serial/EF3BF98430FBCE0FBDF5DA7960C88400.pem -url http://localhost:5003/ocsp -resp_text
        """
        cert = None
        revoke_time = None
        revoke_reason = None

        ocsp_req = ocsp.load_der_ocsp_request(der_ocsp_req)
        serial_number = f"{ocsp_req.serial_number:032X}"
        print(f"serial_number = {serial_number}")

        # Check that we issued the cert
        if self._issued_cert(ocsp_req):
            print("Certificate issued by this CA")
            """
                load the certificate from the utxo
                1 -> get tx id from the tx_cache
                2 -> get the cert from the uxto
            """
            try:
                serial_number_integer = int(serial_number, base=16)
                if tx_cache.cert_status(serial_number_integer):
                    cert = get_cert_from_utxo(serial_number_integer, utxo_set)
                    if cert is None:
                        print('OCSP RESPONDER -> Empty certificate loaded ix tx_cache')
                        cert_status = OCSPCertStatus.UNKNOWN
                    cert_status = OCSPCertStatus.GOOD
                else:
                    expired_cert = tx_cache.look_up_revoked_tx(serial_number_integer)
                    revoke_time = expired_cert.revoke_time
                    revoke_reason = expired_cert.revoke_reason
                    cert = get_cert_from_tx_id(expired_cert.cert_txid, expired_cert.cert_txindex, utxo_set)
                    cert_status = OCSPCertStatus.REVOKED
                    print(f'cert id {serial_number_integer} revoked')

                cert_validate = certificate_authority.get_cert_from_serial_number(serial_number)
                assert cert == cert_validate
            except ValueError as err:
                print(f'Exception caught {err}')
                cert_status = OCSPCertStatus.UNKNOWN

        else:
            print("Certificate not issued by this CA")
            cert_status = OCSPCertStatus.UNKNOWN

        print(f"cert_status = {cert_status}")
        if cert is not None:
            print(f"cert = {cert.subject}")
            return self.create_response(cert, cert_status, revoke_time, revoke_reason, ocsp_req)
        else:
            return None


ocsp_responder = OCSPResponder()
