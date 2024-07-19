#!/bin/bash

# Create network, if not already present
if [ ! "$(docker network inspect ms-node_bitcoin )" ]; then
    echo 'Creating network ms-node_bitcoin'
    docker network create ms-node_bitcoin
fi
# Start container
docker run -it \
    -p 5003:5003 \
    --mount 'type=volume,source=ca-volume,destination=/home/root/easy-rsa' \
    --mount type=bind,source="$(pwd)"/src,target=/app/src \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --network=ms-node_bitcoin \
    --rm camonitor \
    $1 $2

