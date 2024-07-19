#!/bin/bash

# tag
TAG=v1.1

docker buildx build  --platform linux/amd64,linux/arm64 --file Dockerfile --push -t nchain/rnd-prototyping-camonitor:$TAG .
