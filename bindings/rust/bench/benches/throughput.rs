// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::openssl_version_str,
    CipherSuite::{self, *},
    CryptoConfig, Mode, OpenSslHarness, RustlsHarness, S2NHarness, TlsBenchHarness,
};
use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup,
    Criterion, Throughput,
};

pub fn bench_throughput_cipher_suite(c: &mut Criterion) {
    let mut shared_buf = [0u8; 100000];

    fn bench_throughput_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        shared_buf: &mut [u8],
        cipher_suite: CipherSuite,
    ) {
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    let mut harness = T::new(
                        CryptoConfig::new(cipher_suite, Default::default(), Default::default()),
                        Default::default(),
                        Default::default(),
                    )
                    .unwrap();
                    harness.handshake().unwrap();
                    harness
                },
                |harness| {
                    harness
                        .transfer(Mode::Client, black_box(shared_buf))
                        .unwrap();
                    harness
                        .transfer(Mode::Server, black_box(shared_buf))
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }

    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NHarness>(
            &mut bench_group,
            "s2n-tls",
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(not(feature = "s2n-only"))]
        {
            bench_throughput_for_library::<RustlsHarness>(
                &mut bench_group,
                "rustls",
                &mut shared_buf,
                cipher_suite,
            );
            bench_throughput_for_library::<OpenSslHarness>(
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
