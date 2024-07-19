#!/bin/bash

# Delete existing certs & keys
rm src/certs/localhost.crt
rm src/certs/localhost.key

# Generate new cert
curl -X 'POST' \
  'http://localhost:5003/create_cert?name=localhost' \
  -H 'accept: application/json' \
  -d ''

# Download new cert
curl -X 'GET' 'http://localhost:5003/cert_file?name=localhost' \
  -H 'accept: application/json' > src/certs/localhost.crt

# and key
curl -X 'GET' \
  'http://localhost:5003/key_file?name=localhost' \
  -H 'accept: application/json' > src/certs/localhost.key
