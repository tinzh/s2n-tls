#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# sets bench crate to use aws-lc-rs instead of ring for rustls

set -e

# go to bench directory
pushd "$(dirname "$0")" > /dev/null
bench_dir="$(pwd)"

# clone rustls to bench/target/rustls and checkout compatible version
rm -rf target/rustls
git clone https://github.com/rustls/rustls target/rustls
cd target/rustls
git checkout 'v/0.21.5'
cd ../..

# clone aws-lc-rs to bench/target/aws-lc-rs
rm -rf target/aws-lc-rs
git clone https://github.com/aws/aws-lc-rs target/aws-lc-rs
cd target/aws-lc-rs/aws-lc-rs
git submodule init
git submodule update

# change aws-lc-rs to look like ring
sed -i 's|name = .*|name = "ring"| ; s|version = "1.2.1"|version = "0.16.20"|' Cargo.toml

# go to dir with rustls crate
cd ../../rustls
rustls_dir="$(pwd)"/rustls

# tell Cargo to use custom rustls and aws-lc-rs
cd $bench_dir
mkdir -p .cargo
# if .cargo/config.toml doesn't already have an [patch.crates-io] header, add it
if [[ ! -f .cargo/config.toml || "$(cat .cargo/config.toml)" != *"[patch.crates-io]"* ]]; then
echo "[patch.crates-io]
rustls = { path = \"$rustls_dir\" }
ring = { path = \"target/aws-lc-rs/aws-lc-rs\" }" >> .cargo/config.toml
fi

rm -rf target/release

popd > /dev/null
