//! Linux-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use bincode::{deserialize, serialize};
use log::{error, info};
use nix::sys::socket::{setsockopt, sockopt};
use std::{net::TcpListener, os::unix::io::AsRawFd};

use veracruz_utils::platform::{linux::{receive_buffer, send_buffer}, vm::{RuntimeManagerMessage, VMStatus}};

use crate::managers::{session_manager, RuntimeManagerError};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that `0.0.0.0` implies all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// Port to listen for incoming messages on.
const INCOMING_PORT: &'static str = "5022";

////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

pub fn linux_main() -> Result<(), RuntimeManagerError> {
    env_logger::init();

    let listen_on = format!("{}:{}", INCOMING_ADDRESS, INCOMING_PORT);

    let listener = TcpListener::bind(&listen_on).map_err(|ioerr| {
        error!(
            "Failed to bind TCP listener to address {}.  Error produced: {}.",
            listen_on, ioerr
        );
        RuntimeManagerError::IOError(ioerr)
    })?;

    info!("TCP listener created on {}.", listen_on);

    if !setsockopt(listener.as_raw_fd(), sockopt::ReuseAddr, &true).is_ok() {
        error!("Failed to set socket options.");
        return Err(RuntimeManagerError::SetSockOptFailed);
    }

    let (mut fd, client_addr) = listener.accept().map_err(|ioerr| {
        error!(
            "Failed to accept any incoming TCP connection.  Error produced: {}.",
            ioerr
        );
        RuntimeManagerError::IOError(ioerr)
    })?;

    info!("TCP listener connected on {:?}.", client_addr);

    loop {
        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|err| {
            error!("Failed to receive message.  Error produced: {}.", err);
            RuntimeManagerError::IOError(err)
        })?;

        let received_message: RuntimeManagerMessage =
            deserialize(&received_buffer).map_err(|derr| {
                error!(
                    "Failed to deserialize received message.  Error produced: {}.",
                    derr
                );
                RuntimeManagerError::BincodeError(derr)
            })?;

        info!("Received message: {:?}.", received_message);

        let return_message = match received_message {
            RuntimeManagerMessage::Initialize(policy_json) => {
                info!("Initializing enclave.");
                session_manager::init_session_manager(&policy_json).map_err(|serr| {
                    error!(
                        "Failed to initialize session manager.  Error produced: {}.",
                        serr
                    );
                    serr
                })?;
                RuntimeManagerMessage::Status(VMStatus::Success)
            }
            RuntimeManagerMessage::NewTLSSession => {
                info!("Initiating new TLS session.");

                session_manager::new_session()
                    .map(|session_id| RuntimeManagerMessage::TLSSession(session_id))
                    .unwrap_or_else(|e| {
                        error!(
                            "Could not initiate new TLS session.  Error produced: {:?}.",
                            e
                        );
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::CloseTLSSession(session_id) => {
                info!("Closing TLS session.");

                session_manager::close_session(session_id)
                    .map(|_e| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to close TLS session.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetEnclaveName => {
                info!("Retrieving enclave name.");

                session_manager::get_enclave_name()
                    .map(|name| RuntimeManagerMessage::EnclaveName(name))
                    .unwrap_or_else(|e| {
                        error!("Could not retrieve enclave name.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetEnclaveCert => {
                info!("Retrieving enclave certificate.");

                session_manager::get_enclave_cert_pem()
                    .map(|cert| RuntimeManagerMessage::EnclaveCert(cert))
                    .unwrap_or_else(|e| {
                        error!(
                            "Could not retrieve enclave certificate.  Error produced: {:?}.",
                            e
                        );
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSDataNeeded(session_id) => {
                info!("Checking whether TLS data is needed.");

                session_manager::get_data_needed(session_id)
                    .map(|needed| RuntimeManagerMessage::TLSDataNeeded(needed))
                    .unwrap_or_else(|e|{
                        error!("Failed to check whether further TLS data needed.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSData(session_id) => {
                info!("Retrieving TLS data.");

                session_manager::get_data(session_id)
                    .map(|(active, data)| RuntimeManagerMessage::TLSData(data, active))
                    .unwrap_or_else(|e| {
                        error!("Failed to retrieve TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::SendTLSData(session_id, tls_data) => {
                info!("Sending TLS data.");

                session_manager::send_data(session_id, &tls_data)
                    .map(|_| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to send TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetPSAAttestationToken(_challenge) => unimplemented!(),
            RuntimeManagerMessage::ResetEnclave => {
                info!("Resetting enclave.  Note that this is currently not implemented.");

                RuntimeManagerMessage::Status(VMStatus::Success)
            }
            otherwise => {
                error!("Received unknown or unimplemented opcode: {:?}.", otherwise);
                RuntimeManagerMessage::Status(VMStatus::Unimplemented)
            }
        };

        let return_buffer = serialize(&return_message).map_err(|serr| {
            error!(
                "Failed to serialize returned message.  Error produced: {}.",
                serr
            );
            RuntimeManagerError::BincodeError(serr)
        })?;

        info!("Sending message: {:?}.", return_message);

        send_buffer(&mut fd, &return_buffer).map_err(|e| {
            error!("Failed to send message.  Error produced: {}.", e);
            RuntimeManagerError::IOError(e)
        })?;
    }

    Ok(())
}
