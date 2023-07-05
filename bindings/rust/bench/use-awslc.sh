#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# generates rust bindings with aws-lc
# if bench was built previously, use `cargo clean` to remove old s2n-tls build
# all arguments taken in are passed to `cargo bench`
# dependencies: Go (make sure it's on PATH!)

# aws-lc build directory: s2n-tls/libcrypto-build/
# aws-lc install directory: s2n-tls/libcrypto-root/

set -e

# go to repo directory from calling script anywhere
pushd "$(dirname "$0")/../../../"
repo_dir=`pwd`


# ----- build aws-lc -----

# clean up past builds
rm -rf libcrypto-root
mkdir libcrypto-root
rm -rf libcrypto-build/aws-lc

# clone clean aws-lc
cd libcrypto-build/
git clone --depth=1 https://github.com/aws/aws-lc
cd aws-lc

# build aws-lc to libcrypto-root
cmake -B build -DCMAKE_INSTALL_PREFIX=$repo_dir/libcrypto-root/ -DBUILD_TESTING=OFF -DBUILD_LIBSSL=ON
cmake --build ./build -j $(nproc)
make -C build install

cmake -B build -DCMAKE_INSTALL_PREFIX=$repo_dir/libcrypto-root/ -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_LIBSSL=ON
cmake --build ./build -j $(nproc)
make -C build install


# ----- use rustls with aws-lc-rs -----

# clone rustls to bench/target/rustls
cd $repo_dir/bindings/rust/bench
cargo clean
git clone --depth=1 https://github.com/rustls/rustls target/rustls

# change rustls to use aws-lc-rs
sed -i 's/ring = .*/ring = { package = "aws-lc-rs" }/' target/rustls/rustls/Cargo.toml

# change bench to use custom rustls
sed -i 's/rustls = .*/rustls = { path = "target\/rustls\/rustls" }/' Cargo.toml


# ------ build s2n-tls + bindings -----

cd $repo_dir
cmake . -Bbuild -DCMAKE_PREFIX_PATH=$repo_dir/libcrypto-root/ -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF
cmake --build ./build -j $(nproc)

# tell linker where s2n-tls was built
export S2N_TLS_LIB_DIR=$repo_dir/build/lib
export S2N_TLS_INCLUDE_DIR=$repo_dir/api
export LD_LIBRARY_PATH=$openssl_lib_dir:$S2N_TLS_LIB_DIR:$LD_LIBRARY_PATH

# generate bindings with aws-lc
cd bindings/rust
cargo clean
./generate.sh


# ----- bench everything (including memory) -----

cd bench
# ./memory-bench.sh
cargo bench $@

popd
