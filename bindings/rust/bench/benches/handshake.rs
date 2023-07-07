// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::openssl_version_str,
    CryptoConfig,
    ECGroup::{self, *},
    HandshakeType::{self, *},
    OpenSslHarness, RustlsHarness, S2NHarness,
    SigType::{self, *},
    TlsBenchHarness,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};

pub fn bench_handshake_params(c: &mut Criterion) {
    fn bench_handshake_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        handshake_type: HandshakeType,
        ec_group: ECGroup,
        sig_type: SigType,
    ) {
        // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
        // timing only includes negotiation, not config/connection initialization
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    T::new(
                        CryptoConfig::new(Default::default(), ec_group, sig_type),
                        handshake_type,
                        Default::default(),
                    )
                },
                |harness| {
                    // if harness invalid, do nothing but don't panic
                    // useful for historical performance bench
                    if let Ok(harness) = harness {
                        let _ = harness.handshake();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    for handshake_type in [Full, mTLS] {
        for ec_group in [SECP256R1, X25519] {
            for sig_type in [Rsa2048, Rsa4096, Ec384] {
                let mut bench_group = c.benchmark_group(format!(
                    "handshake-{:?}-{:?}-{:?}",
                    handshake_type, ec_group, sig_type
                ));
                bench_handshake_for_library::<S2NHarness>(
                    &mut bench_group,
                    "s2n-tls",
                    handshake_type,
                    ec_group,
                    sig_type,
                );
                #[cfg(not(feature = "s2n-only"))]
                {
                    bench_handshake_for_library::<RustlsHarness>(
                        &mut bench_group,
                        "rustls",
                        handshake_type,
                        ec_group,
                        sig_type,
                    );
                    bench_handshake_for_library::<OpenSslHarness>(
                        &mut bench_group,
                        &openssl_version_str(),
                        handshake_type,
                        ec_group,
                        sig_type,
                    );
                }
            }
        }
    }
}

criterion_group!(benches, bench_handshake_params);
criterion_main!(benches);
