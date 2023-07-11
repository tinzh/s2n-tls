// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{get_cert_path, PemType};
use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    fs::read_to_string,
    io::{ErrorKind, Read, Write},
    rc::Rc,
};

pub fn read_to_bytes(pem_type: &PemType, sig_type: &SigType) -> Vec<u8> {
    read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

pub fn openssl_version_str() -> String {
    let version_num = openssl::version::number() as u64;
    let patch: u8 = (version_num >> 4) as u8;
    let fix = (version_num >> 12) as u8;
    let minor = (version_num >> 20) as u8;
    let major = (version_num >> 28) as u8;
    format!(
        "openssl{}.{}.{}{}",
        major,
        minor,
        fix,
        (b'a' + patch - 1) as char
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CipherSuite {
    #[default]
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ECGroup {
    SECP256R1,
    #[default]
    X25519,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SigType {
    Rsa2048,
    Rsa4096,
    #[default]
    Ec384,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub ec_group: ECGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, ec_group: ECGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            ec_group,
            sig_type,
        }
    }
}

pub trait TlsConnection: Sized {
    type Config;
    /// Default connection
    fn default(mode: Mode) -> Result<Self, Box<dyn Error>> {
        Self::new(
            mode,
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    /// Make a config
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self::Config, Box<dyn Error>>;

    /// Make connection from existing config and buffer
    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>>;

    /// Initialize buffers, configs, and connections (pre-handshake)
    fn new(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
        buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        Self::new_from_config(
            &Self::make_config(mode, crypto_config, handshake_type)?,
            buffer,
        )
    }

    /// Run one handshake step on initialized connections
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    fn handshake_completed(&self) -> bool;

    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    fn negotiated_tls13(&self) -> bool;

    /// Send application data to ConnectedBuffer
    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;

    /// Receive application data from ConnectedBuffer
    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>>;

    /// Release buffers in connections
    fn shrink_connection_buffers(&mut self);

    /// Release connected buffers for IO between connections
    fn shrink_connected_buffer(&mut self);

    /// Get internal connected buffer
    fn clone_connected_buffer(&self) -> ConnectedBuffer;
}

pub struct TlsConnPair<C: TlsConnection, S: TlsConnection> {
    client: C,
    server: S,
}

impl<C: TlsConnection, S: TlsConnection> Default for TlsConnPair<C, S> {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default()).unwrap()
    }
}

impl<C: TlsConnection, S: TlsConnection> TlsConnPair<C, S> {
    /// Initialize buffers, configs, and connections (pre-handshake)
    pub fn wrap(client: C, server: S) -> Self {
        assert!(
            client.clone_connected_buffer() == server.clone_connected_buffer().inverse(),
            "connected buffers don't match"
        );
        Self { client, server }
    }

    pub fn unwrap(self) -> (C, S) {
        (self.client, self.server)
    }

    pub fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: C::new(
                Mode::Client,
                crypto_config,
                handshake_type,
                connected_buffer.clone().inverse(),
            )?,
            server: S::new(
                Mode::Server,
                crypto_config,
                handshake_type,
                connected_buffer,
            )?,
        })
    }

    /// Run handshake on initialized connections
    /// Returns error if handshake has already completed
    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.client.handshake()?;
            self.server.handshake()?;
        }
        Ok(())
    }

    /// Checks if handshake is finished for both client and server
    pub fn handshake_completed(&self) -> bool {
        self.client.handshake_completed() && self.server.handshake_completed()
    }

    /// Get negotiated cipher suite
    pub fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        assert!(self.handshake_completed());
        assert!(self.client.get_negotiated_cipher_suite() == self.server.get_negotiated_cipher_suite());
        self.client.get_negotiated_cipher_suite()
    }

    /// Get whether or negotiated version is TLS1.3
    pub fn negotiated_tls13(&self) -> bool {
        self.client.negotiated_tls13() && self.server.negotiated_tls13()
    }

    /// Send data from client to server and then from server to client
    pub fn round_trip_transfer(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        // send data from client to server
        self.client.send(data)?;
        self.server.recv(data)?;

        // send data from server to client
        self.server.send(data)?;
        self.client.recv(data)?;

        Ok(())
    }

    /// Release buffers in connections
    pub fn shrink_connection_buffers(&mut self) {
        self.client.shrink_connection_buffers();
        self.server.shrink_connection_buffers();
    }

    /// Release connected buffers for IO between connections
    pub fn shrink_connected_buffers(&mut self) {
        self.client.shrink_connected_buffer();
        self.server.shrink_connected_buffer();
    }
}

/// Wrapper of two shared buffers to pass as stream
/// This wrapper `read()`s into one buffer and `write()`s to another
#[derive(Clone, Eq)]
pub struct ConnectedBuffer {
    recv: Rc<RefCell<VecDeque<u8>>>,
    send: Rc<RefCell<VecDeque<u8>>>,
}

impl PartialEq for ConnectedBuffer {
    fn eq(&self, other: &ConnectedBuffer) -> bool {
        Rc::ptr_eq(&self.recv, &other.recv) && Rc::ptr_eq(&self.send, &other.send)
    }
}

impl ConnectedBuffer {
    /// Make a new struct with new internal buffers
    pub fn new() -> Self {
        let recv = Rc::new(RefCell::new(VecDeque::new()));
        let send = Rc::new(RefCell::new(VecDeque::new()));

        // prevent resizing of buffers, useful for memory bench
        recv.borrow_mut().reserve(10000);
        send.borrow_mut().reserve(10000);

        ConnectedBuffer { recv, send }
    }

    /// Make a new struct that shares internal buffers but swapped, ex.
    /// `write()` writes to the buffer that the inverse `read()`s from
    pub fn inverse(self) -> Self {
        Self {
            recv: self.send,
            send: self.recv,
        }
    }

    /// Clear buffers and shrink to fit
    pub fn shrink(&mut self) {
        self.recv.borrow_mut().clear();
        self.recv.borrow_mut().shrink_to_fit();
        self.send.borrow_mut().clear();
        self.send.borrow_mut().shrink_to_fit();
    }
}

impl Read for ConnectedBuffer {
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, std::io::Error> {
        let res = self.recv.borrow_mut().read(dest);
        match res {
            // rustls expects WouldBlock on read of length 0
            Ok(0) => Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking")),
            Ok(len) => Ok(len),
            Err(err) => Err(err),
        }
    }
}

impl Write for ConnectedBuffer {
    fn write(&mut self, src: &[u8]) -> Result<usize, std::io::Error> {
        self.send.borrow_mut().write(src)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(()) // data already available to destination
    }
}

impl Default for ConnectedBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
macro_rules! test_tls_bench_harnesses {
    ($($lib_name:ident: $conn_type:ty,)*) => {
    $(
        mod $lib_name {
            use super::*;
            use CipherSuite::*;
            use ECGroup::*;
            use HandshakeType::*;
            use SigType::*;

            #[test]
            fn test_handshake_config() {
                let (mut harness, mut crypto_config);
                for handshake_type in [ServerAuth, MutualAuth] {
                    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                        for ec_group in [SECP256R1, X25519] {
                            for sig_type in [Ec384, Rsa2048, Rsa4096] {
                                crypto_config = CryptoConfig::new(cipher_suite, ec_group, sig_type);
                                harness = TlsConnPair::<$conn_type, $conn_type>::new(crypto_config, handshake_type, Default::default()).unwrap();

                                assert!(!harness.handshake_completed());
                                harness.handshake().unwrap();
                                assert!(harness.handshake_completed());

                                assert!(harness.negotiated_tls13());
                                assert_eq!(cipher_suite, harness.get_negotiated_cipher_suite());
                            }
                        }
                    }
                }
            }

            #[test]
            fn test_transfer() {
                // use a large buffer to test across TLS record boundaries
                let mut buf = [0x56u8; 1000000];
                let (mut harness, mut crypto_config);
                for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
                    for ec_group in [SECP256R1, X25519] {
                        crypto_config = CryptoConfig::new(cipher_suite, ec_group, Default::default());
                        harness = TlsConnPair::<$conn_type, $conn_type>::new(crypto_config, Default::default(), Default::default()).unwrap();
                        harness.handshake().unwrap();
                        harness.round_trip_transfer(&mut buf).unwrap();
                    }
                }
            }
        }
    )*
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair};

    test_tls_bench_harnesses! {
        s2n_tls: OpenSslConnection,
        rustls: RustlsConnection,
        openssl: S2NConnection,
    }

    #[test]
    fn test_mixed_conns() -> () {
        test_mixed_conns_res().unwrap();
    }

    fn test_mixed_conns_res() -> Result<(), Box<dyn Error>> {
        test_handshake::<S2NConnection, RustlsConnection>();
        test_handshake::<S2NConnection, OpenSslConnection>();
        test_handshake::<RustlsConnection, S2NConnection>();
        test_handshake::<RustlsConnection, OpenSslConnection>();
        test_handshake::<OpenSslConnection, S2NConnection>();
        test_handshake::<OpenSslConnection, RustlsConnection>();
        Ok(())
    }

    fn test_handshake<C: TlsConnection, S: TlsConnection>() {
        let mut harness = TlsConnPair::<C, S>::default();
        assert!(!harness.handshake_completed());
        harness.handshake().unwrap();
        assert!(harness.handshake_completed());

        assert!(harness.negotiated_tls13());
        assert_eq!(CipherSuite::default(), harness.get_negotiated_cipher_suite());
    }
}
