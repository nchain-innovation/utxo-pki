import requests
from typing import MutableMapping, Any
from tx_engine import Script


def get_financing_service_status(finance_srv: MutableMapping[str, Any]) -> bool:
    address = finance_srv["address"]
    client_id = finance_srv["client_id"]

    headers = {'content-type': 'application/json'}
    url: str = address + "/status"

    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        js = res.json()

        # cycle through the clients looking for "client_id"
        for client in js["clients"]:
            if client["client_id"] == client_id:
                print(f'Financing Service found: client -> {client}')
                return True
        return False

    else:
        print(f"Financing Service returned bad status, {res.status_code}")
        return False


# get the balance from finance service
# http://127.0.0.1:8080/balance/id1
def get_balance(finance_srv: MutableMapping[str, Any]) -> int:
    address = finance_srv["address"]
    client_id = finance_srv["client_id"]

    headers = {'content-type': 'application/json'}
    url: str = address + "/balance/" + client_id

    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        js = res.json()
        if js["status"] == "Success":
            balance = js["Balance"]["confirmed"]
            print(f'Financing Service: balance -> {balance}')
            return balance
        else:
            print('Error getting balance from finance service')
            return 0
    else:
        print(f"Financing Service returned bad status, {res.status_code}")
        return 0


# /fund/{client_id}/{satoshi}/{no_of_outpoints}/{multiple_tx}/{locking_script}
# curl -X POST http://127.0.0.1:8080/fund/id1/123/1/false/0000
# fund transaction from finance service
def fund_transaction(finance_srv: MutableMapping[str, Any], amount: int, locking_script: Script) -> dict:
    address = finance_srv["address"]
    client_id = finance_srv["client_id"]
    print("Financing service: fund_transaction")
    print(f'  amount -> {amount}')
    print(f'  locking_script -> {locking_script.to_string()}')
    print(f'  client_id -> {client_id}')
    print(f'  address -> {address}')

    headers = {'content-type': 'application/json'}
    # the length of the locking script is removed from the front ([2:] syntax)
    url: str = address + "/fund/" + client_id + "/" + str(amount) + "/1/false/" + locking_script.serialize().hex()[2:]

    res = requests.post(url, headers=headers)
    if res.status_code == 200:
        js = res.json()
        if js["status"] == "Success":
            print("Success funding transaction")
            print(js)
            return js
        else:
            print('Error funding transaction from finance service')
            print(f'js -> {js}')
            return {}
    else:
        print(f"Financing Service returned bad status, {res.status_code}")
        return {}
