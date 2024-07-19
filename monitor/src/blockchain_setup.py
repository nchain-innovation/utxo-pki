
from typing import Any, MutableMapping, Dict

from mopengine_dist.tx.bsv_client_insandbox import BSVClientInSandbox
from mopengine_dist.engine.keys import wif_to_key

SATOSHIS = 100000000


def is_ms_node(config: MutableMapping[str, Any]) -> bool:
    """ Return true if we are connected to ms-node service.
    """
    return config["type"] == "insandbox" and config['network_type'] == "test" and config['address'] == "node1:18332"


def generate_blocks(bsv_client: BSVClientInSandbox) -> None:
    """ Generate blocks, if required
    """
    block_count = bsv_client.get_block_count()
    print(f"block_count = {block_count}")
    if block_count <= 101:
        # Generate 101 blocks
        print("Generating blocks")
        bsv_client.generate_blocks(n=101)


def blockchain_setup(config: MutableMapping[str, Any], bsv_client: BSVClientInSandbox) -> Dict[str, str]:
    """ Sets up accounts and credit for on blockchain ready for demonstration.
        Note that this works for the ms-node blockchain.
    """
    generate_blocks(bsv_client)

    # Fund the funding account
    funding_key = wif_to_key(config["cert_wallets"]["funding_key"])
    funding_balance = config["cert_wallets"]["funding_balance"]

    addr = funding_key.address
    # Make sure that the Node reports this address
    bsv_client.import_address(addr)

    balance = bsv_client.get_balance(addr, confirmations=0)
    total_balance = balance['confirmed'] + balance['unconfirmed']
    delta = funding_balance - total_balance

    # Pay account the required balance
    if delta > 0:
        delta = delta / SATOSHIS
        print(f"send {delta} to {addr}")
        bsv_client.send_to_address(addr, amount=delta)

    # Create a block
    bsv_client.generate_blocks(n=1)

    # List user accounts
    accounts = bsv_client.list_accounts()
    for wallet in accounts:
        for acc in wallet:
            if acc[0] == addr:
                print(acc)

    return {
        "result": "success"
    }
