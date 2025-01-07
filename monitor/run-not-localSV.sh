#!/bin/bash

# Start container
docker run -it \
    -p 5003:5003 \
    --mount 'type=volume,source=ca-volume,destination=/home/root/easy-rsa' \
    --mount type=bind,source="$(pwd)"/src,target=/app/src \
    --mount type=bind,source="$(pwd)/data",target=/app/data \
    --rm camonitor \
    $1 $2

