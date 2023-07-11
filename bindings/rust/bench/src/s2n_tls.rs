// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, ConnectedBuffer, CryptoConfig, ECGroup, HandshakeType, Mode,
        TlsConnection,
    },
    PemType::*,
};
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::Builder,
    connection::Connection,
    enums::{Blinding, ClientAuthType, Version},
    security::Policy,
};
use std::{
    error::Error,
    ffi::c_void,
    io::{ErrorKind, Read, Write},
    os::raw::c_int,
    pin::Pin,
};

pub struct S2NConfig {
    mode: Mode,
    config: s2n_tls::config::Config,
}

pub struct S2NConnection {
    // UnsafeCell is needed b/c client and server share *mut to IO buffers
    // Pin<Box<T>> is to ensure long-term *mut to IO buffers remain valid
    connected_buffer: Pin<Box<ConnectedBuffer>>,
    connection: Connection,
    handshake_completed: bool,
}

/// Custom callback for verifying hostnames. Rustls requires checking hostnames,
/// so this is to make a fair comparison
struct HostNameHandler<'a> {
    expected_server_name: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.expected_server_name == hostname
    }
}

impl S2NConnection {
    /// Unsafe callback for custom IO C API
    ///
    /// s2n-tls IO is usually used with file descriptors to a TCP socket, but we
    /// reduce overhead and outside noise with a local buffer for benchmarking
    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &mut *(context as *mut ConnectedBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        context.write(data).unwrap() as _
    }

    /// Unsafe callback for custom IO C API
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &mut *(context as *mut ConnectedBuffer);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        context.flush().unwrap();
        match context.read(data) {
            Err(err) => {
                if let ErrorKind::WouldBlock = err.kind() {
                    errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                    -1
                } else {
                    panic!("{err:?}");
                }
            }
            Ok(len) => len as _,
        }
    }
}

impl TlsConnection for S2NConnection {
    type Config = S2NConfig;

    /// Make a config
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self::Config, Box<dyn Error>> {
        let security_policy = match (crypto_config.cipher_suite, crypto_config.ec_group) {
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::SECP256R1) => "20230317",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::SECP256R1) => "20190802",
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::X25519) => "default_tls13",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::X25519) => "20190801",
        };

        let mut builder = Builder::new();
        builder
            .set_security_policy(&Policy::from_version(security_policy)?)?
            .wipe_trust_store()?
            .set_client_auth_type(match handshake_type {
                HandshakeType::ServerAuth => ClientAuthType::None,
                HandshakeType::MutualAuth => ClientAuthType::Required,
            })?;

        // add CA cert if needed
        if handshake_type == HandshakeType::MutualAuth || mode == Mode::Client {
            builder
                .trust_pem(read_to_bytes(&CACert, &crypto_config.sig_type).as_slice())?
                .set_verify_host_callback(HostNameHandler {
                    expected_server_name: "localhost",
                })?;
        }

        // add auth certs if needed
        if mode == Mode::Server || handshake_type == HandshakeType::MutualAuth {
            let (cert_chain_path, key_path) = match mode {
                Mode::Server => (&ServerCertChain, &ServerKey),
                Mode::Client => (&ClientCertChain, &ClientKey),
            };
            builder.load_pem(
                read_to_bytes(cert_chain_path, &crypto_config.sig_type).as_slice(),
                read_to_bytes(key_path, &crypto_config.sig_type).as_slice(),
            )?;
        }

        Ok(S2NConfig {
            mode,
            config: builder.build()?,
        })
    }

    /// Make connection from existing config and buffer
    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        let mode = match config.mode {
            Mode::Client => s2n_tls::enums::Mode::Client,
            Mode::Server => s2n_tls::enums::Mode::Server,
        };

        let mut connected_buffer = Box::pin(connected_buffer);

        let mut connection = Connection::new(mode);
        connection
            .set_blinding(Blinding::SelfService)?
            .set_config(config.config.clone())?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            connection
                .set_send_context(&mut *connected_buffer as *mut ConnectedBuffer as *mut c_void)?
                .set_receive_context(
                    &mut *connected_buffer as *mut ConnectedBuffer as *mut c_void,
                )?;
        }

        Ok(Self {
            connected_buffer,
            connection,
            handshake_completed: false,
        })
    }

    /// Run one handshake step on initialized connections
    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        self.handshake_completed = self
            .connection
            .poll_negotiate()
            .map(|r| r.unwrap())
            .is_ready();
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.handshake_completed
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.connection.cipher_suite().unwrap() {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection.actual_protocol_version().unwrap() == Version::TLS13
    }

    /// Send application data to ConnectedBuffer
    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        assert!(self.connection.poll_send(data).is_ready());
        assert!(self.connection.poll_flush().is_ready());
        Ok(())
    }

    /// Receive application data from ConnectedBuffer
    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        assert!(self.connection.poll_recv(data).is_ready());
        Ok(())
    }

    /// Release buffers in connections
    fn shrink_connection_buffers(&mut self) {
        self.connection.release_buffers().unwrap();
    }

    /// Release connected buffers for IO between connections
    fn shrink_connected_buffer(&mut self) {
        self.connected_buffer.shrink();
    }

    /// Get internal connected buffer
    fn clone_connected_buffer(&self) -> ConnectedBuffer {
        (*self.connected_buffer).clone()
    }
}
