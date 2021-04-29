use bincode::{deserialize, serialize, Error as BincodeError};
use env_logger;
use err_derive::Error;
use log::{error, info};
use nix::{
    sys::socket::{setsockopt, sockopt},
    Error as NixError,
};
use serde::{Deserialize, Serialize};
use std::{io::Error as IOError, net::TcpListener, os::unix::io::AsRawFd};
use veracruz_utils::platform::linux::{receive_buffer, send_buffer};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that "0.0.0.0" means that we listen on
/// all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// Incoming port to listen on.00000
const INCOMING_PORT: &'static str = "5021";

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
    /// Acknowledgment that the root enclave is to shutdown.
    ShuttingDown,
}

////////////////////////////////////////////////////////////////////////////////
// Responses to message stimuli.
////////////////////////////////////////////////////////////////////////////////

/// Returns the version of the trusted runtime's software stack.  Note that on
/// Linux this is mocked up, as the attestation process is completely insecure.
fn get_firmware_version() -> &'static str {
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

    let _ignore = entry_point().map_err(|e| {
        eprintln!(
            "Linux root enclave runtime failure.  Error produced: {:?}.",
            e
        )
    });
}
