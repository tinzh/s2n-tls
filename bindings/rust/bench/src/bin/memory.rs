// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::ConnectedBuffer, OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair, Mode::{Client, Server, self},
    TlsConnection,
};
use std::{fs::create_dir_all, error::Error};

fn bench_library_size<T: TlsConnection>(xtree_name: &str) -> Result<(), Box<dyn Error>> {
    create_dir_all("target/memory/xtree").unwrap();
    let mut harness = TlsConnPair::<T, T>::default();
    harness.handshake()?;
    harness.shrink_connection_buffers();
    harness.shrink_connected_buffers();

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory target/memory/xtree/{xtree_name}.out"))?;
    Ok(())
}

fn memory_bench_conn<T: TlsConnection>(mode: Mode, dir_name: &str) -> Result<(), Box<dyn Error>> {
    println!("testing {dir_name}");

    create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    create_dir_all("target/memory/xtree").unwrap();

    let mut connections = Vec::new();
    connections.reserve(100);

    // reserve space for buffers before benching
    let mut buffers = Vec::new();
    buffers.reserve(100);
    for _ in 0..100 {
        buffers.push(ConnectedBuffer::new());
    }

    // handshake one harness to initalize libraries
    let mut harness = TlsConnPair::<T, T>::default();
    harness.handshake().unwrap();

    // make configs
    let client_config = T::make_config(Client, Default::default(), Default::default())?;
    let server_config = T::make_config(Server, Default::default(), Default::default())?;

    // tell massif to take initial memory snapshot
    crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/0.snapshot")).unwrap();

    // make and handshake 100 harness
    for i in 1..101 {
        let client_conn = T::new_from_config(&client_config, buffers.pop().unwrap())?;
        let server_conn = T::new_from_config(&server_config, client_conn.clone_connected_buffer().inverse())?;
        let mut harness = TlsConnPair::<T, T>::wrap(client_conn, server_conn);
        harness.handshake()?;
        harness.shrink_connection_buffers();

        connections.push(match mode {
            Mode::Client => harness.unwrap().0,
            Mode::Server => harness.unwrap().1,
        });

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/{i}.snapshot"))?;
    }

    // release all ConnectedBuffers to have accurate xtree
    for connection in connections.iter_mut() {
        connection.shrink_connected_buffer();
    }

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory target/memory/xtree/{dir_name}.out"))?;

    Ok(())
}

fn memory_bench<C: TlsConnection, S: TlsConnection>(dir_name: &str) -> Result<(), Box<dyn Error>> {
    println!("testing {dir_name}");

    create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    create_dir_all("target/memory/xtree").unwrap();

    let mut harnesses = Vec::new();
    harnesses.reserve(100);

    // reserve space for buffers before benching
    let mut buffers = Vec::new();
    buffers.reserve(100);
    for _ in 0..100 {
        buffers.push(ConnectedBuffer::new());
    }

    // handshake one harness to initalize libraries
    let mut harness = TlsConnPair::<C, S>::default();
    harness.handshake().unwrap();

    // make configs
    let client_config = C::make_config(Client, Default::default(), Default::default())?;
    let server_config = S::make_config(Server, Default::default(), Default::default())?;

    // tell massif to take initial memory snapshot
    crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/0.snapshot")).unwrap();

    // make and handshake 100 harness
    for i in 1..101 {
        // reserve just enough space for one harness
        harnesses.reserve(i + 1);

        let client_conn = C::new_from_config(&client_config, buffers.pop().unwrap())?;
        let server_conn = S::new_from_config(&server_config, client_conn.clone_connected_buffer().inverse())?;
        let mut harness = TlsConnPair::<C, S>::wrap(client_conn, server_conn);
        harness.handshake()?;
        harness.shrink_connection_buffers();
        harnesses.push(harness);

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/{i}.snapshot"))?;
    }

    // release all ConnectedBuffers to have accurate xtree
    for harness in harnesses.iter_mut() {
        harness.shrink_connected_buffers();
    }

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory target/memory/xtree/{dir_name}.out"))?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    assert!(!cfg!(debug_assertions), "need to run in release mode");

    memory_bench::<S2NConnection, RustlsConnection>("s2n-tls__rustls")?;
    memory_bench::<RustlsConnection, S2NConnection>("rustls__s2n-tls")?;
    memory_bench::<OpenSslConnection, OpenSslConnection>("openssl")?;
    memory_bench::<RustlsConnection, RustlsConnection>("rustls")?;
    memory_bench::<S2NConnection, S2NConnection>("s2n-tls")?;

    memory_bench_conn::<S2NConnection>(Mode::Client, "s2n-tls_client")?;
    memory_bench_conn::<S2NConnection>(Mode::Server, "s2n-tls_server")?;
    memory_bench_conn::<RustlsConnection>(Mode::Client, "rustls_client")?;
    memory_bench_conn::<RustlsConnection>(Mode::Server, "rustls_server")?;

    bench_library_size::<S2NConnection>("s2n-tls_library")?;
    bench_library_size::<S2NConnection>("rustls_library")?;

    Ok(())
}
