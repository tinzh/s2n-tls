// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite::*, CryptoConfig, ECGroup::*, Mode, OpenSslHarness, RustlsHarness, S2NHarness,
    TlsBenchHarness,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};

pub fn bench_bulk_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk-transfer");

    let mut shared_buf = [0u8; 100000];
    group.throughput(Throughput::Bytes(shared_buf.len() as u64));

    macro_rules! bench_bulk_transfer_for_libraries {
        ($(($lib_name:expr, $lib_type:ty),)*) => {
        $(
            // generate all inputs (s2n-tls objects) before benchmarking handshakes
            group.bench_function($lib_name, |b| {
                b.iter_batched_ref(
                    || {
                        let mut harness = <$lib_type>::default().unwrap();
                        harness.handshake().unwrap();
                        harness
                    },
                    |harness| {
                        harness.transfer(Mode::Client, black_box(&mut shared_buf)).unwrap();
                        harness.transfer(Mode::Server, black_box(&mut shared_buf)).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        )*
        }
    }

    bench_bulk_transfer_for_libraries! {
        ("s2n-tls", S2NHarness),
        ("rustls", RustlsHarness),
        ("openssl", OpenSslHarness),
    }

    group.finish();
}

pub fn bench_bulk_transfer_cipher_suite(c: &mut Criterion) {
    let mut shared_buf = [0u8; 100000];

    macro_rules! bench_bulk_transfer_for_libraries {
        ($cipher_suite:ident, $(($lib_name:expr, $lib_type:ty),)*) => {
            // separate out each cipher_suite/ec_group pair to different groups
            let mut group = c.benchmark_group(format!("bulk-transfer-{:?}", $cipher_suite));
            group.throughput(Throughput::Bytes(shared_buf.len() as u64));
            $(
                // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
                // timing only includes negotiation, not config/connection initialization
                group.bench_function($lib_name, |b| {
                    b.iter_batched_ref(
                        || {
                            let mut harness = <$lib_type>::new(&CryptoConfig { $cipher_suite, ec_group: X25519 }).unwrap();
                            harness.handshake().unwrap();
                            harness
                        },
                        |harness| {
                            harness.transfer(Mode::Client, black_box(&mut shared_buf)).unwrap();
                            harness.transfer(Mode::Server, black_box(&mut shared_buf)).unwrap();
                        },
                        BatchSize::SmallInput,
                    )
                });
            )*
            group.finish();
        }
    }

    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
        bench_bulk_transfer_for_libraries! {
                cipher_suite,
                ("s2n-tls", S2NHarness),
                ("rustls", RustlsHarness),
                ("openssl", OpenSslHarness),
        }
    }
}

criterion_group!(
    benches,
    bench_bulk_transfer,
    bench_bulk_transfer_cipher_suite
);
criterion_main!(benches);
