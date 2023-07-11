#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    #[default]
    Full,
    mTLS,
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

pub trait TlsBenchConnection {
    type Config;
    fn default();
    fn new();
    fn handshake();
    fn handshake_complete();
    fn get_negotiated_cipher_suite();
    fn negotiated_tls13();
    fn send();
    fn recv();
    fn shrink_internal_buffers();
    fn shrink_connected_buffers();

    fn clone_connected_buffer_inverse();
    fn new_from_config(config: &Config, mode: Mode);
    fn get_config(params: CryptoConfig) -> Config;
}

pub trait TlsBenchHarness: Sized {
    /// Default harness
    fn default() -> Result<Self, Box<dyn Error>> {
        Self::new(Default::default(), Default::default(), Default::default())
    }

    /// Initialize buffers, configs, and connections (pre-handshake)
    fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
        buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run handshake on initialized connections
    /// Returns error if handshake has already completed
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    /// Checks if handshake is finished for both client and server
    fn handshake_completed(&self) -> bool;

    /// Get negotiated cipher suite
    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    /// Get whether or negotiated version is TLS1.3
    fn negotiated_tls13(&self) -> bool;

    /// Transfer given data one-way between connections
    fn transfer(&mut self, sender: Mode, data: &mut [u8]) -> Result<(), Box<dyn Error>>;

    /// Release buffers in connections
    fn shrink_connection_buffers(&mut self);

    /// Release connected buffers for IO between connections
    fn shrink_connected_buffers(&mut self);
}