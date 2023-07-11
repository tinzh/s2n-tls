// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::openssl_version_str,
    CipherSuite::{self, *},
    CryptoConfig, OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair, TlsConnection,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};

pub fn bench_throughput_cipher_suite(c: &mut Criterion) {
    let mut shared_buf = [0u8; 100000];

    fn bench_throughput_for_library<T: TlsConnection>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        shared_buf: &mut [u8],
        cipher_suite: CipherSuite,
    ) {
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    let mut harness = TlsConnPair::<T, T>::new(
                        CryptoConfig::new(cipher_suite, Default::default(), Default::default()),
                        Default::default(),
                        Default::default(),
                    )
                    .unwrap();
                    harness.handshake().unwrap();
                    harness
                },
                |harness| {
                    harness.round_trip_transfer(shared_buf).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }

    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NConnection>(
            &mut bench_group,
            "s2n-tls",
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(not(feature = "s2n-only"))]
        {
            bench_throughput_for_library::<RustlsConnection>(
                &mut bench_group,
                "rustls",
                &mut shared_buf,
                cipher_suite,
            );
            bench_throughput_for_library::<OpenSslConnection>(
                &mut bench_group,
                &openssl_version_str(),
                &mut shared_buf,
                cipher_suite,
            );
        }
    }
}

criterion_group!(benches, bench_throughput_cipher_suite);
criterion_main!(benches);
