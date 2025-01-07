#!/bin/bash

flake8 --ignore=E501,E131,E402 --exclude=monitor/src/tools  monitor/src

mypy --check-untyped-defs --ignore-missing-imports monitor/src/*.py monitor/src/tests/*.py webserver/src/*.py
