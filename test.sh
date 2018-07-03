#!/bin/bash

set -e

pushd () {
    command pushd "$@" > /dev/null
}

popd () {
    command popd "$@" > /dev/null
}

pushd btd
go test
popd

pushd crypto
go test
popd
