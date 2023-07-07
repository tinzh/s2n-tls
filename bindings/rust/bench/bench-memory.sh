#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use Valgrind and Massif to heap profile the memory taken by different TLS libraries
# Uses Valgrind monitor commands to take snapshots of heap size while making connections

# Snapshots get stored in target memory/[library-name]/ as [number].snapshot

set -e

pushd "$(dirname "$0")"

cargo build --release --bin memory

bench () {
    valgrind --tool=massif --massif-out-file="target/memory/$1/massif.out" --time-unit=ms "${@:2}" target/release/memory $1
}

bench s2n-tls $@
bench rustls $@
bench openssl $@

cargo bench --bench memory

popd
