#!/bin/bash

# Start container
docker run -it \
    -p 5005:5005 \
    --mount 'type=volume,source=ca-volume,destination=/home/root/easy-rsa' \
    --mount type=bind,source="$(pwd)"/src,target=/app/src \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --rm webserver \
    $1 $2

