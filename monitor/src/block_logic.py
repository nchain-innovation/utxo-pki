from tx_engine.interface.blockchain_interface import BlockchainInterface
from transaction_cache import tx_cache


class SVStatus:
    """ This class tracks the status of the blockchain
    """
    def __init__(self):
        self.last_block = 0

    def has_new_block(self, bsv_client: BlockchainInterface) -> bool:
        """ Return true if there is a new block on the chain
        """
        block_count = bsv_client.get_block_count()
        if block_count > self.last_block:
            self.last_block = block_count
            return True
        else:
            return False

    def new_block_event(self, bsv_client: BlockchainInterface) -> None:
        """ This handles the new block
        """
        print("new_block_event")
        block_count = bsv_client.get_block_count()
        print(f"block_count = {block_count}")

        # a list of transactions with out merkle proofs.
        # for each tx -> check if it has confirmations & a block hash
        tx_list = tx_cache.lookup_tx_without_merkle_proofs()
        for txid in tx_list.keys():
            tx_info = bsv_client.get_transaction(txid)
            if tx_info is not None:
                if tx_info["confirmations"] > 0:
                    # get the block
                    block_info = bsv_client.get_block(tx_info["blockhash"])
                    assert block_info is not None
                    merkle_proof = bsv_client.get_merkle_proof(tx_info["blockhash"], txid)
                    tx_cache.update_tx_cert_merkle_info(tx_list[txid], tx_info["blockhash"], block_info["merkleroot"], merkle_proof)


sv_status = SVStatus()
