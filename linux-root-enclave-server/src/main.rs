//! The Linux root envlave server.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for copyright
//! and licensing information.

use bincode::{deserialize, serialize, Error as BincodeError};
use clap::{App, Arg};
use env_logger;
use err_derive::Error;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::process::Child;
use std::{
    io::Error as IOError,
    net::TcpStream,
    path::PathBuf,
    process::{exit, Command},
    str::FromStr,
};
use url::Url;
use veracruz_utils::platform::linux::{receive_buffer, send_buffer};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The default URL of the Veracruz proxy attestation server.
const DEFAULT_PROXY_ATTESTATION_SERVER_URL: &'static str = "https://localhost:8080";
/// The IP address that the Linux root enclave server is listening on.
const LINUX_ROOT_ENCLAVE_IP_ADDRESS: &'static str = "127.0.0.1";
/// The port that the Linux root enclave is listening on.
const LINUX_ROOT_ENCLAVE_PORT: &'static str = "5021";

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

/// Various error modes that the Linux root enclave server can exhibit.
#[derive(Debug, Error)]
enum LinuxRootEnclaveServerError {
    #[error(display = "A command line argument was not correctly formed and could not be parsed.")]
    /// A command line argument was not correctly formed and could not be parsed.
    CommandLineParsingError,
    #[error(display = "A program (subprocess) could not be initialized.")]
    /// A subprocess could not be started.
    ProgramInitializationError,
    #[error(
        display = "A message could not be serialized or deserialized.  Error produced: {}.",
        _0
    )]
    /// There was an error serializing or deserializing a message.
    SerializationError(BincodeError),
    #[error(display = "A socket-related error occurred.  Error produced: {}.", _0)]
    /// A socket operation failed to complete, and returned an error code.
    SocketError(IOError),
    /// An unexpected response was received from the Linux root enclave.
    #[error(display = "An unexpected response was received from the Linux root enclave.")]
    UnexpectedResponse,
}

////////////////////////////////////////////////////////////////////////////////
// Command-line parsing.
////////////////////////////////////////////////////////////////////////////////

/// Struct capturing the command line arguments passed to the utility.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CommandLineConfiguration {
    /// Path to the Linux root enclave binary.
    linux_root_enclave_path: PathBuf,
    /// URL of the proxy attestation server.
    proxy_attestation_server_url: Url,
    /// Optional number of attempts to retry a failed sent message.  Here,
    /// `None` denotes no upper bound on the number of connection attempts.
    max_retry_attempts: Option<u64>,
}

impl CommandLineConfiguration {
    /// Creates a new `CommandLineConfiguration` with the proxy attestation
    /// server's URL set to `localhost`, infinite retry attempts, and an empty
    /// path to the Linux root enclave.
    #[inline]
    pub fn new() -> Self {
        Self {
            linux_root_enclave_path: PathBuf::new(),
            proxy_attestation_server_url: Url::parse(DEFAULT_PROXY_ATTESTATION_SERVER_URL)
                .expect("Internal invariant failed: parsing of localhost URL failed."),
            max_retry_attempts: None,
        }
    }

    /// Returns the maximum number of retry attempts to make when trying to
    /// establish a connection with an external service.
    #[inline]
    pub fn max_retry_attempts(&self) -> Option<&u64> {
        self.max_retry_attempts.as_ref()
    }

    /// Returns the URL of the proxy attestation service.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &Url {
        &self.proxy_attestation_server_url
    }

    /// Returns the path of the Linux root enclave.
    #[inline]
    pub fn linux_root_enclave_path(&self) -> &PathBuf {
        &self.linux_root_enclave_path
    }

    /// Sets the maximum number of retry attempts to make when trying to
    /// establish a connection with an external service to `attempts`.
    #[inline]
    pub fn set_max_retry_attempts<T>(&mut self, attempts: T) -> &mut Self
    where
        T: Into<u64>,
    {
        self.max_retry_attempts = Some(attempts.into());
        self
    }

    /// Sets the URL of the proxy attestation service to `url`.
    #[inline]
    pub fn set_proxy_attestation_server_url<T>(&mut self, url: T) -> &mut Self
    where
        T: Into<Url>,
    {
        self.proxy_attestation_server_url = url.into();
        self
    }

    /// Sets the path of the Linux root enclave to `path`.
    #[inline]
    pub fn set_linux_root_enclave_path(&mut self, path: PathBuf) -> &mut Self {
        self.linux_root_enclave_path = path;
        self
    }
}

////////////////////////////////////////////////////////////////////////////////
// Messaging.
////////////////////////////////////////////////////////////////////////////////

/// Outgoing messages to the Linux root enclave, instructing it to perform some
/// act.  These are sent serialized in `bincode` format.
///
/// TODO: this can be moved into `veracruz-utils` as it is shared material.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
enum LinuxRootEnclaveMessage {
    /// A request to get the firmware version of the software executing inside
    /// the enclave.
    GetFirmwareVersion,
    /// A request to perform a native attestation of the runtime enclave.
    /// Note that we use PSA attestation for this step, but the attestation is
    /// "fake", offering no real value other than for demonstrative purposes.
    GetNativeAttestation(Vec<u8>, i32),
    /// A request to perform a proxy attestation of the runtime enclave.
    /// Note that we use PSA attestation, again, for this step, but the
    /// attestation is "fake", offering no real value other than for
    /// demonstrative purposes.
    GetProxyAttestation(Vec<u8>, Vec<u8>, String),
    /// A request to shutdown the root enclave.
    Shutdown,
}

/// Responses produced by the Linux root enclave after receiving and processing
/// a `LinuxRootEnclaveMessage` element, above.
///
/// TODO: this can be moved into `veracruz-utils` as it is shared material.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
enum LinuxRootEnclaveResponse<'a> {
    /// The firmware version of the software executing inside the runtime
    /// enclave.  For Linux, this is mocked up.
    FirmwareVersion(&'a str),
    /// The token produced by the native attestation process.
    NativeAttestationToken(Vec<u8>),
    /// The token produced by the proxy attestation process.
    ProxyAttestationToken(Vec<u8>),
    /// Acknowledgment that the root enclave is to shutdown.
    ShuttingDown,
    /// The interacting party relayed an unknown or unimplemented message.
    UnknownMessage,
}

////////////////////////////////////////////////////////////////////////////////
// The Linux root enclave.
////////////////////////////////////////////////////////////////////////////////

/// A type capturing information needed to communicate with the Linux root
/// enclave.  This consists of a handle to the Linux root enclave's process, and
/// an active TCP connection between the current process and the Linux root
/// enclave used for communication between the two.
struct LinuxRootEnclave {
    /// The Linux root enclave process.
    process: Child,
    /// The TCP connection used to communicate with the Linux root enclave
    /// process.
    socket: TcpStream,
}

impl LinuxRootEnclave {
    /// Creates a new `LinuxRootEnclave` from a handle to the child process of
    /// the Linux root enclave, `process`, and an active TCP stream between the
    /// current process and the Linux root enclave, `socket`.
    #[inline]
    pub fn new(process: Child, socket: TcpStream) -> Self {
        Self { process, socket }
    }

    pub fn firmware_version(&mut self) -> Result<String, LinuxRootEnclaveServerError> {
        info!("Fetching firmware version from Linux root enclave.");

        let message = serialize(&LinuxRootEnclaveMessage::GetFirmwareVersion).map_err(|e| {
            error!(
                "Failed to serialize GetFirmwareVersion message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveServerError::SerializationError(e)
        })?;

        send_buffer(&mut self.socket, &message).map_err(|e| {
            error!(
                "Failed to transmit GetFirmwareVersion message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveServerError::SocketError(e)
        })?;

        info!("GetFirmwareVersion message sent.  Awaiting response.");

        let recv_buffer = receive_buffer(&self.socket).map_err(|e| {
            error!(
                "Failed to receive response to GetFirmwareVersion message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveServerError::SocketError(e)
        })?;

        let response: LinuxRootEnclaveResponse = deserialize(&recv_buffer).map_err(|e| {
            error!("Failed to deserialize response to GetFirmwareVersion message.  Error produced: {}.", e);
            LinuxRootEnclaveServerError::UnexpectedResponse
        })?;

        match response {
            LinuxRootEnclaveResponse::FirmwareVersion(version) => {
                info!("Received firmware version {} in response.", version);
                Ok(String::from(version))
            }
            otherwise => {
                error!(
                    "Received unexpected response from Linux root enclave: {:?}.",
                    otherwise
                );
                Err(LinuxRootEnclaveServerError::UnexpectedResponse)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Attestation.
////////////////////////////////////////////////////////////////////////////////

/// Starts the Linux root enclave and establishes a TCP connection to it for
/// communication using the information in `configuration`.  Returns `Err(err)`
/// if this process fails for any reason, and `Ok(enclave)` otherwise.
fn start_linux_root_enclave(
    configuration: &CommandLineConfiguration,
) -> Result<LinuxRootEnclave, LinuxRootEnclaveServerError> {
    info!(
        "Starting the Linux root enclave at: {:?}.",
        configuration.linux_root_enclave_path()
    );

    let mut child_process = Command::new(configuration.linux_root_enclave_path())
        .spawn()
        .map_err(|_e| {
            error!(
                "Failed to start Linux root enclave at {:?}.",
                configuration.linux_root_enclave_path()
            );
            LinuxRootEnclaveServerError::ProgramInitializationError
        })?;

    let root_enclave_address = format!(
        "{}:{}",
        LINUX_ROOT_ENCLAVE_IP_ADDRESS, LINUX_ROOT_ENCLAVE_PORT
    );

    info!(
        "Linux root enclave initialized, establishing connection on {}.",
        root_enclave_address
    );

    let socket = TcpStream::connect(&root_enclave_address).map_err(|e| {
        error!(
            "Failed to establish socket on {}, killing Linux root enclave.  Error produced: {}.",
            root_enclave_address, e
        );

        /* We're in the process of terminating anyway, so just eat any errors
          that are produced, here.
        */
        let _ = child_process.kill();

        LinuxRootEnclaveServerError::SocketError(e)
    })?;

    info!("TCP connection to Linux root enclave established.");

    Ok(LinuxRootEnclave::new(child_process, socket))
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

fn entry_point() -> Result<(), LinuxRootEnclaveServerError> {
    let app = App::new("linux-root-enclave-server")
        .arg(
            Arg::new("proxy-attestation-server-url")
                .short('u')
                .about("The URL of the Veracruz proxy attestation server.")
                .default_missing_value(DEFAULT_PROXY_ATTESTATION_SERVER_URL),
        )
        .arg(
            Arg::new("max-retry-attempts")
                .short('r')
                .about(
                    "The maximum number of retry attempts when trying to contact an external service (infinite if no limit supplied).",
                ),
        )
        .arg(
            Arg::new("linux-root-enclave-path")
                .short('l')
                .about("The path to the Linux root enclave executable.")
                .required(true)
        );

    let matches = app.get_matches();
    let mut configuration = CommandLineConfiguration::new();

    if let Some(url) = matches.value_of("proxy-attestation-server-url") {
        let url = Url::parse(url).map_err(|_e| {
            error!("Failed to parse Veracruz proxy attestation server URL.");
            LinuxRootEnclaveServerError::CommandLineParsingError
        })?;

        configuration.set_proxy_attestation_server_url(url);
    } else {
        info!(
            "No proxy attestation server URL provided.  Using default: {}.",
            DEFAULT_PROXY_ATTESTATION_SERVER_URL
        );
    }

    if let Some(max_retries) = matches.value_of("max-retry-attempts") {
        let retries = u64::from_str(max_retries).map_err(|_e| {
            error!("Failed to parse maximum retry attempts.");
            LinuxRootEnclaveServerError::CommandLineParsingError
        })?;

        configuration.set_max_retry_attempts(retries);
    } else {
        info!("No maximum retry number supplied.  Using infinite retries.");
    }

    if let Some(path) = matches.value_of("linux-root-enclave-path") {
        let path = PathBuf::from_str(path).map_err(|_e| {
            error!("Could not parse the path to the Linux root enclave binary.");
            LinuxRootEnclaveServerError::CommandLineParsingError
        })?;
        configuration.set_linux_root_enclave_path(path);
    } else {
        error!("No path to the Linux root enclave binary supplied.");
        return Err(LinuxRootEnclaveServerError::CommandLineParsingError);
    }

    let _enclave = start_linux_root_enclave(&configuration)?;

    Ok(())
}

fn main() {
    env_logger::init();

    entry_point().map_err(|e| {
        eprintln!("Error: {}.", e);
        exit(-1);
    });
}
