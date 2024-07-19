# UTXO PKI System Setup
This document describes the stages required to setup the UTXO-PKI system. At a high level these are
1) Build the docker `monitor` image
2) Setup the Certificate Authority
3) Create and install the certificates
4) Set up the Blockchain accounts and funds
5) Check the system works

## Dependencies
This project has the following dependencies:
* `Docker` - This ensures that the project dependencies are encapsulated in a container.
* `MS-Node` - A bitcoin-bsv node in regtest mode with supporting software including WhatsOnChain, mAPI and RPC interfaces. Note that this is optional, the alternative would be to use `SV Testnet` or `Mainnet`.

# 1) Build The Docker Monitor Image
To build the docker images associated with the service run the following comand in the `monitor` directory.
```bash
cd monitor
./build.sh
```

# To Run the Monitor
Finally once the Monitor has been configured and the CA setup, to run the Monitor
```bash
cd monitor
./run.sh
```

The REST API/web interface is avalible at http://localhost:5003/docs.
This interface enables the creation, revoking and checking of certificates.

# To Setup The Certificate Authority
1) Access the REST API/web at http://localhost:5003/docs.
2) Click on Admin/setup_ca `Post`
3) Click on `Try it out`
4) Enter the new ca_name 
3) Click on `Execute`
This will generate a Certificate Authority with the new name


# To Configure Monitor
Before running the monitor you will need to configure which blockchain network it will connect to.
The configuration information is stored in `monitor\data\monitor.toml`.
The Monitor can be connected to:
* BSV Testnet - The public testnet for BSV, this is the default setting
* MS-Node - Regtest Node running on the local machine
## To connect Monitor to BSV Testnet
Place the following lines in `monitor\data\monitor.toml`.
```toml
[bsv_client]
type = "testnet"
network_type = "test"
```
## To connect Monitor to MS-Node
Place the following lines in `monitor\data\monitor.toml`.
```toml
[bsv_client]
type = "insandbox"
user = "bitcoin"
password = "bitcoin"
address = "node1:18332"
network_type = "test"
```


# To Setup The Certificate Authority - Manually

```bash
cd monitor
./run.sh bash
./setup.sh
```
This will create the required directories and the signing CA.
Note that this setup will only have to be performed once as the 
CA state is stored in a docker volume.


