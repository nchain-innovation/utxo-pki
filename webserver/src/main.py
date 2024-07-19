#!/usr/bin/python3

from typing import MutableMapping, Any
import uvicorn
import os

from util import load_config, load_cert_pem_file, load_key_pem_file

def has_cert(config: MutableMapping[str, Any]) -> bool:
    """ Return true if config has the required cert and key to
        establish a HTTPS session
    """
    try:
        has_cert = load_cert_pem_file(config["ssl_certfile"])
        has_key = load_key_pem_file(config["ssl_keyfile"])
        return has_cert is not None and has_key is not None
    except KeyError:
        return False


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
    
    if has_cert(config):
        # Run as HTTPS
        uvicorn.run(
            "rest_api:app",
            host=host,
            port=int(port),
            log_level=config["log_level"],
            reload=config["reload"],
            workers=1,  # Don't change this number unless you understand the full implications of having shared data.
            ssl_keyfile=config["ssl_keyfile"],
            ssl_certfile=config["ssl_certfile"],
        )
    else:
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
    config = load_config("web.toml")
    run_webserver(config["web_interface"])


if __name__ == "__main__":
    main()
