
from typing import Callable, List
from enum import Enum, auto


from tx_engine.interface.blockchain_interface import *
from tx_engine.interface.interface_factory import *

from certificate_authority import certificate_authority


class CertificateStates:
    """ Class to track certificate state
    """
    def __init__(self):
        self.prev_log = []  # Used to keep previous certifcate state

    def get_latest(self) -> List[str]:
        """ Return a list of changes to the certificate states
        """
        logs = certificate_authority.get_certificate_logs()

        # Find the difference between log file and previous file
        diff = [x for x in logs if x not in self.prev_log]

        # Store previous certifcate state
        self.prev_log = logs
        return diff


class FrameworkEvent(Enum):
    ON_CERT_CHANGE = auto()
    ON_BSV_CHANGE = auto()


def always_true(bsv_client: BlockchainInterface):
    """ A predicate that always returns true, for periodic events.
    """
    return True


class Framework:
    """ This class listens for events
        when event occurs the framework calls registered business logic callbacks
    """

    def __init__(self):
        self.callbacks = {}
        self.bsv_callbacks = []
        self.certificate_states = CertificateStates()
        self.bsv_client: BlockchainInterface

    def set_bsv_client(self, client: BlockchainInterface) -> None:
        self.bsv_client = client

    def get_bsv_client(self) -> BlockchainInterface:
        return self.bsv_client

    def register_callback(self, event: FrameworkEvent, callback_function: Callable[[List[str], BlockchainInterface], None]) -> None:
        """ Set the function to be called on an event
        """
        self.callbacks[event] = callback_function

    def register_bsv_callback(self, predicate: Callable[[BlockchainInterface], bool], callback_function: Callable[[BlockchainInterface], None]) -> None:
        """ Set the predicate and function to be called on an event.
            The predicate is called and if it returns true the
            associated callback function is called.
        """
        self.bsv_callbacks.append([predicate, callback_function])

    def register_periodic_bsv_callback(self, callback_function: Callable[[BlockchainInterface], None]) -> None:
        """ Set the callback function to be called on every cycle
        """
        self.bsv_callbacks.append([always_true, callback_function])

    def monitor(self) -> None:
        """ Check for event occuring
            This method is called on startup and every 15 seconds.
        """
        # Check for new certificate states
        cert_changes = self.certificate_states.get_latest()
        if len(cert_changes) > 0:
            if FrameworkEvent.ON_CERT_CHANGE in self.callbacks:
                # Call business logic
                self.callbacks[FrameworkEvent.ON_CERT_CHANGE](cert_changes, self.bsv_client)

        # Check for SV events
        [callback(self.bsv_client)
            for [predicate, callback] in self.bsv_callbacks if predicate(self.bsv_client)]


framework = Framework()
