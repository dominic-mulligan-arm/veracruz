//! The root enclave (read: application) for Linux.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for copyright
//! and licensing information.

use bincode::{deserialize, serialize, Error as BincodeError};
use env_logger;
use err_derive::Error;
use hex::encode;
use lazy_static::lazy_static;
use log::{error, info};
use nix::{
    sys::socket::{setsockopt, sockopt},
    Error as NixError,
};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::{
    env::current_exe, io::Error as IOError, net::TcpListener, os::unix::io::AsRawFd, sync::Mutex,
};
use veracruz_utils::platform::linux::{receive_buffer, send_buffer};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that "0.0.0.0" means that we listen on
/// all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// Incoming port to listen on.00000
const INCOMING_PORT: &'static str = "5021";

lazy_static! {
    static ref DEVICE_PUBLIC_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref DEVICE_PRIVATE_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref DEVICE_ID: Mutex<Option<i32>> = Mutex::new(None);
    static ref LINUX_ROOT_ENCLAVE_PRIVATE_KEY: Vec<u8> = vec![];
    /// This will be populated with the measurement of this binary.
    static ref LINUX_ROOT_ENCLAVE_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

/// Captures all of the different errors that can be produced when trying to
/// listen on, and subsequently process, all of the root enclave messages.
#[derive(Debug, Error)]
enum LinuxRootEnclaveError {
    #[error(
        display = "Failed to serialize or deserialize a message or response.  Error produced: {}.",
        _0
    )]
    /// Bincode failed to serialize or deserialize a message or response.
    BincodeError(BincodeError),
    #[error(
        display = "General IO error when reading or writing files.  Error produced: {}.",
        _0
    )]
    /// There was an error related to the reading or writing of files needed by
    /// the root enclave.
    GeneralIOError(IOError),
    #[error(display = "Failed to set socket options.  Error produced: {}.", _0)]
    /// We were unable to set suitable options on the TCP socket.
    SetSocketOptionsError(NixError),
    #[error(display = "Socket IO error.  Error produced: {}.", _0)]
    /// There was an error either opening, or working with, sockets.
    SocketError(IOError),
}

////////////////////////////////////////////////////////////////////////////////
// Messages.
////////////////////////////////////////////////////////////////////////////////

/// Incoming messages to the Linux root enclave, instructing it to perform some
/// act.  These are sent serialized in `bincode` format.
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
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
enum LinuxRootEnclaveResponse {
    /// The firmware version of the software executing inside the runtime
    /// enclave.  For Linux, this is mocked up.
    FirmwareVersion(&'static str),
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
// Measurement.
////////////////////////////////////////////////////////////////////////////////

/// Computes the measurement of the root enclave binary, using SHA256.  Grabs
/// the path of the binary (i.e. the path of this executable) and reads it,
/// before performing a measurement.  Fails if the path cannot be obtained, or
/// if the resulting filepath cannot be opened for reading.
fn get_root_enclave_hash() -> Result<Vec<u8>, LinuxRootEnclaveError> {
    info!("Computing root enclave measurement.");

    let path = current_exe().map_err(|e| {
        error!(
            "Failed to obtain the path of the runtime enclave.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    let mut file = File::open(path).map_err(|e| {
        error!(
            "Failed to open the runtime enclave binary.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    let mut buffer = Vec::new();
    let length = file.read_to_end(&mut buffer).map_err(|e| {
        error!(
            "Failed to read content of the runtime enclave binary.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    info!("Read {} bytes from binary.", length);

    let measurement = digest(&SHA256, &buffer).as_ref().to_vec();

    info!("Measurement computed: {}.", encode(&measurement));

    Ok(measurement)
}

////////////////////////////////////////////////////////////////////////////////
// Responses to message stimuli.
////////////////////////////////////////////////////////////////////////////////

/// Returns the version of the trusted runtime's software stack.  Note that on
/// Linux this is mocked up, as the attestation process is completely insecure.
#[inline]
fn get_firmware_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn get_native_attestation_token(
    challenge: Vec<u8>,
    device_id: i32,
) -> Result<Vec<u8>, LinuxRootEnclaveError> {
    unimplemented!()
}

fn get_proxy_attestation_token(
    challenge: Vec<u8>,
    native_token: Vec<u8>,
    enclave_name: String,
) -> Result<Vec<u8>, LinuxRootEnclaveError> {
    unimplemented!()
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point for the root enclave.  This sets up a TCP listener and processes
/// messages, deserializing them using Bincode.  Can fail for a variety of
/// reasons, all of which are captured in the `LinuxRootEnclaveError` type.
fn entry_point() -> Result<(), LinuxRootEnclaveError> {
    info!("Linux root enclave initializing.");

    let listen_on = format!("{}:{}", INCOMING_ADDRESS, INCOMING_PORT);

    info!("Starting listening on {}.", listen_on);

    let listener = TcpListener::bind(&listen_on).map_err(|e| {
        error!("Failed to open TCP socket.  Error produced: {}.", e);
        LinuxRootEnclaveError::SocketError(e)
    })?;

    info!("Started listening on {}.", listen_on);

    if let Err(e) = setsockopt(listener.as_raw_fd(), sockopt::ReuseAddr, &true) {
        error!("Failed to set socket options.  Error produced: {}.", e);
        return Err(LinuxRootEnclaveError::SetSocketOptionsError(e));
    }

    let (mut fd, client_addr) = listener.accept().map_err(|ioerr| {
        error!(
            "Failed to accept any incoming TCP connection.  Error produced: {}.",
            ioerr
        );
        LinuxRootEnclaveError::SocketError(ioerr)
    })?;

    info!("TCP listener connected on {:?}.", client_addr);

    /* Set to `true` when a request to shutdown is received, breaking the
      message processing loop, below.
    */
    let mut shutdown = false;

    while !shutdown {
        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|e| {
            error!("Failed to receive message.  Error produced: {}.", e);
            LinuxRootEnclaveError::SocketError(e)
        })?;

        let received_message = deserialize(&received_buffer).map_err(|e| {
            error!(
                "Failed to deserialize received message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::BincodeError(e)
        })?;

        info!("Received message: {:?}.", received_message);

        let response = match received_message {
            LinuxRootEnclaveMessage::GetFirmwareVersion => {
                info!("Computing firmware version.");

                Ok(LinuxRootEnclaveResponse::FirmwareVersion(
                    get_firmware_version(),
                ))
            }
            LinuxRootEnclaveMessage::Shutdown => {
                info!("Shutting down the Linux root enclave.");

                shutdown = true;

                Ok(LinuxRootEnclaveResponse::ShuttingDown)
            }
            LinuxRootEnclaveMessage::GetNativeAttestation(challenge, device_id) => {
                info!("Computing a native attestation token.");

                Ok(LinuxRootEnclaveResponse::NativeAttestationToken(
                    get_native_attestation_token(challenge, device_id)?,
                ))
            }
            LinuxRootEnclaveMessage::GetProxyAttestation(challenge, native_token, enclave_name) => {
                info!("Computing a proxy attestation token.");

                Ok(LinuxRootEnclaveResponse::ProxyAttestationToken(
                    get_proxy_attestation_token(challenge, native_token, enclave_name)?,
                ))
            }
        }?;

        info!("Producing response: {:?}.", response);

        let response_buffer = serialize(&response).map_err(|e| {
            error!(
                "Failed to serialize response message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::BincodeError(e)
        })?;

        info!("Sending message with length: {}.", response_buffer.len());

        send_buffer(&mut fd, &response_buffer).map_err(|e| {
            error!("Failed to send response.  Error produced: {}.", e);
            LinuxRootEnclaveError::SocketError(e)
        })?;
    }

    Ok(())
}

/// Main entry point for the program.  Calls `entry_point` and pretty-prints
/// any error that was produced.  Initializes the logging service.
fn main() {
    env_logger::init();

    /* 1. Generate a device-specific public/private key-pair. */

    let _ignore = entry_point().map_err(|e| {
        eprintln!(
            "Linux root enclave runtime failure.  Error produced: {:?}.",
            e
        )
    });
}
