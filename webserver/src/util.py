from typing import List, Any, MutableMapping, Optional, Union
from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.hazmat.primitives.asymmetric import (
    dh, #DHPrivateKey,
    ed25519, #Ed25519PrivateKey,
    ed448, #Ed448PrivateKey,
    rsa, #RSAPrivateKey,
    dsa, #DSAPrivateKey,
    ec, #EllipticCurvePrivateKey,
    x25519, #X25519PrivateKey,
    x448, #X448PrivateKey,s
)

import toml
import os

# Define a type alias for all supported key types
PrivateKeyTypes = Union[
    dh.DHPrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
]


def load_config(filename="bsv.toml") -> MutableMapping[str, Any]:
    """ Load config from provided toml file
    """
    try:
        with open(filename, "r") as f:
            config = toml.load(f)
        return config
    except FileNotFoundError as e:
        print(e)
        return {}


def load_file(fname: str) -> List[str]:
    """ Given filename return contents as list
    """
    try:
        with open(fname, "r") as f:
            contents = f.readlines()
        return contents
    except FileNotFoundError as e:
        print(e)
        return []


def create_dir(dirname: str) -> None:
    """ Create dir if required
    """
    if not os.path.isdir(dirname):
        os.mkdir(dirname)


def remove_path_and_extension(filename: str) -> str:
    """ Given a file name remove the file path and extension
    """
    base = os.path.basename(filename)
    return os.path.splitext(base)[0]


def load_cert_pem_file(fname: str) -> Optional[Certificate]:
    """ Given a filename return contents as a certificate
    """
    try:
        with open(fname, mode="rb") as f:
            cert_bytes = f.read()
    except FileNotFoundError as e:
        print(e)
        return None
    else:
        return load_pem_x509_certificate(cert_bytes)


def load_key_pem_file(fname: str) -> Optional[PrivateKeyTypes]:
    """ Given a filename return contents as a key
    """
    try:
        with open(fname, mode="rb") as f:
            key_bytes = f.read()
    except FileNotFoundError as e:
        print(e)
        return None
    else:
        return load_pem_private_key(data=key_bytes, password=None)


def write_file_contents(filename: str, contents: str) -> None:
    """ Write the file contents to the provided filename
    """
    try:
        with open(filename, "wt") as f:
            f.write(contents)
    except FileNotFoundError as e:
        print(e)
