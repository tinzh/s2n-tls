// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::ConnectedBuffer,
    Mode::{Client, Server},
    OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair, TlsConnection,
};
use std::{error::Error, fs::create_dir_all};
use structopt::{clap::arg_enum, StructOpt};

arg_enum! {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum MemoryBenchMode {
        Client,
        Server,
        Pair,
    }
}

impl Default for MemoryBenchMode {
    fn default() -> Self {
        MemoryBenchMode::Pair
    }
}

enum TlsStruct<T: TlsConnection> {
    Client(T),
    Server(T),
    Pair(TlsConnPair<T, T>),
}

fn memory_bench_library_size<T: TlsConnection>(lib_name: &str) -> Result<(), Box<dyn Error>> {
    create_dir_all("target/memory/xtree").unwrap();
    let mut harness = TlsConnPair::<T, T>::default();
    harness.handshake()?;
    harness.shrink_connection_buffers();
    harness.shrink_connected_buffers();

    // take xtree snapshot
    crabgrind::monitor_command(format!(
        "xtmemory target/memory/xtree/{lib_name}_library.out"
    ))?;
    Ok(())
}

fn memory_bench_conn<T: TlsConnection>(
    mode: MemoryBenchMode,
    name: &str,
    generate_new_config_each_time: bool,
    keep_internal_buffers: bool,
) -> Result<(), Box<dyn Error>> {
    let dir_name = match mode {
        MemoryBenchMode::Client => format!("{name}_client"),
        MemoryBenchMode::Server => format!("{name}_server"),
        MemoryBenchMode::Pair => format!("{name}_pair"),
    };

    println!("testing {dir_name}");

    create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    create_dir_all("target/memory/xtree").unwrap();

    let mut tls_structs = Vec::new();
    tls_structs.reserve_exact(100);

    // reserve space for buffers before benching
    let mut buffers = Vec::new();
    buffers.reserve_exact(100);
    for _ in 0..100 {
        let mut buffer = ConnectedBuffer::new();
        buffer.shrink();
        buffers.push(buffer);
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
        let (client_conn, server_conn);
        if generate_new_config_each_time {
            client_conn = T::new(
                Client,
                Default::default(),
                Default::default(),
                buffers.pop().unwrap(),
            )?;
            server_conn = T::new(
                Server,
                Default::default(),
                Default::default(),
                client_conn.connected_buffer().clone_inverse(),
            )?;
        } else {
            client_conn = T::new_from_config(&client_config, buffers.pop().unwrap())?;
            server_conn = T::new_from_config(
                &server_config,
                client_conn.connected_buffer().clone_inverse(),
            )?;
        }
        let mut harness = TlsConnPair::<T, T>::wrap(client_conn, server_conn);
        harness.handshake()?;
        if !keep_internal_buffers {
            harness.shrink_connection_buffers();
        }
        harness.shrink_connected_buffers();

        tls_structs.push(match mode {
            MemoryBenchMode::Client => TlsStruct::Client(harness.unwrap().0),
            MemoryBenchMode::Server => TlsStruct::Server(harness.unwrap().1),
            MemoryBenchMode::Pair => TlsStruct::Pair(harness),
        });

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/{i}.snapshot"))?;
    }

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory target/memory/xtree/{dir_name}.out"))?;

    Ok(())
}

fn memory_bench<T: TlsConnection>(name: &str, opt: &Opt) -> Result<(), Box<dyn Error>> {
    memory_bench_conn::<T>(
        opt.mode,
        name,
        opt.generate_new_config_each_time,
        opt.keep_internal_buffers,
    )?;

    if opt.mode == MemoryBenchMode::Pair {
        memory_bench_conn::<T>(MemoryBenchMode::Client, name, opt.generate_new_config_each_time, opt.keep_internal_buffers)?;
        memory_bench_conn::<T>(MemoryBenchMode::Server, name, opt.generate_new_config_each_time, opt.keep_internal_buffers)?;
        memory_bench_library_size::<T>(name)?;
    }

    Ok(())
}

#[derive(Default, StructOpt)]
struct Opt {
    #[structopt()]
    lib_name: Option<String>,

    #[structopt(possible_values = &MemoryBenchMode::variants(), case_insensitive = true, default_value = "pair")]
    mode: MemoryBenchMode,

    #[structopt(short = "-c")]
    generate_new_config_each_time: bool,

    #[structopt(short = "-b")]
    keep_internal_buffers: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    assert!(!cfg!(debug_assertions), "need to run in release mode");

    let opt = Opt::from_args();

    match &opt.lib_name {
        Some(lib_name) => match lib_name.as_str() {
            "s2n-tls" => memory_bench::<S2NConnection>("s2n-tls", &opt)?,
            "rustls" => memory_bench::<RustlsConnection>("rustls", &opt)?,
            "openssl" => memory_bench::<OpenSslConnection>("openssl", &opt)?,
            _ => panic!("invalid argument"),
        },
        None => {
            memory_bench::<S2NConnection>("s2n-tls", &opt)?;
            memory_bench::<OpenSslConnection>("openssl", &opt)?;
            memory_bench::<RustlsConnection>("rustls", &opt)?;
        }
    }

    Ok(())
}
