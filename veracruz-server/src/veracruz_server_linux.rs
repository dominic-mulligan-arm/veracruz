//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {

    use log::{info, error};

    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use std::{process::{Command, Child}, io::Write, net::TcpStream, thread::sleep, time::Duration};
    use veracruz_utils::{VeracruzPolicy, RuntimeManagerMessage, send_buffer, receive_buffer, VMStatus};
    use bincode::{serialize, deserialize};

    const RUNTIME_MANAGER_PATH: &'static str = "../runtime-manager/target/release/runtime_manager_enclave";
    const RUNTIME_MANAGER_PORT: &'static str = "5022";
    const RUNTIME_MANAGER_ADDRESS: &'static str = "127.0.0.1";
    const RUNTIME_MANAGER_SPAWN_DELAY_SECONDS: u64 = 3;

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Runtime Manager Enclave.
    pub struct VeracruzServerLinux {
        /// A handle to the Runtime Manager Enclave's process.
        child_process: Child,
        /// The socket used to communicate with the Runtime Manager Enclave.
        socket: TcpStream
    }

    impl VeracruzServer for VeracruzServerLinux {
        fn new(policy: &str) -> Result<Self, VeracruzServerError> where
            Self: Sized {

            info!("Creating new Veracruz Server instance for Linux.");

            let policy_json = VeracruzPolicy::from_json(policy).map_err(|e| {
                error!("Failed to parse Veracruz policy file.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            info!("Successfully parsed JSON policy file.");

            info!("Launching Runtime Manager enclave: {}.", RUNTIME_MANAGER_PATH);

            let mut child_process = Command::new(RUNTIME_MANAGER_PATH).spawn().map_err(|e| {
                error!("Failed to launch Runtime Manager enclave.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
            })?;

            info!("Runtime Manager enclave spawned.");

            sleep(Duration::from_secs(RUNTIME_MANAGER_SPAWN_DELAY_SECONDS));

            let runtime_manager_address = format!("{}:{}", RUNTIME_MANAGER_ADDRESS, RUNTIME_MANAGER_PORT);

            info!("Connecting to Runtime Manager enclave on {}.", runtime_manager_address);

            let mut socket =
                TcpStream::connect(runtime_manager_address).map_err(|error| {
                    error!("Failed to connect to Runtime Manager enclave.  Error produced: {:?}.", error);
                    error!("Killing Runtime Manager enclave.");

                    child_process.kill();
                    error
                })?;

            info!("Now connected to Runtime Manager enclave.");

            info!("Sending Initialize message.");

            let initialize = serialize(&RuntimeManagerMessage::Initialize(policy.to_string()))
                .map_err(|e| {
                    error!("Failed to serialize enclave initialization message.  Error produced: {:?}.", e);
                    VeracruzServerError::BincodeError(*e)
                })?;

            send_buffer(&mut socket, &initialize).map_err(|e| {
                error!("Failed to transmit enclave initialization message.  Error produced: {:?}.", e);
                e
            })?;

            let init_buffer = receive_buffer(&socket).map_err(|e| {
                error!("Failed to receive reply to enclave initialization message.  Error produced: {:?}.", e);
                e
            })?;

            let status: RuntimeManagerMessage = deserialize(&init_buffer).map_err(|e| {
                error!("Failed to deserialize reply to enclave initialization message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            info!("Enclave fully initialized.");

            return match status {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    Ok(VeracruzServerLinux {
                        child_process,
                        socket
                    })
                }
                RuntimeManagerMessage::Status(status) =>
                    Err(VeracruzServerError::NitroStatus(status)),
                _otherwise =>
                    Err(VeracruzServerError::RuntimeManagerMessageStatus(message))
            }
        }

        fn proxy_psa_attestation_get_token(&mut self, challenge: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError> {
            unimplemented!()
        }

        fn plaintext_data(&mut self, data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            info!("Sending {} bytes of plaintext data to enclave.", data.len());

            let parsed = transport_protocol::parse_runtime_manager_request(&data)?;

            if parsed.has_request_proxy_psa_attestation_token() {
                info!("Sending proxy PSA attestation token request.");

                let rpat = parsed.get_request_proxy_psa_attestation_token();
                let challenge = transport_protocol::parse_request_proxy_psa_attestation_token(rpat);

                let (psa_attestation_token, pubkey, device_id) =
                    self.proxy_psa_attestation_get_token(challenge).map_err(|e| {
                        error!("Failed to retrieve PSA proxy attestation token.  Error produced: {:?}.", e);
                        e
                    })?;

                let serialized_pat = transport_protocol::serialize_proxy_psa_attestation_token(
                    &psa_attestation_token,
                    &pubkey,
                    device_id,
                ).map_err(|e| {
                    error!("Failed to serialize PSA proxy attestation token.  Error produced: {:?}.", e);
                    VeracruzServerError::TransportProtocolError(e)
                })?;

                info!("Proxy PSA attestation token retrieved.");

                Ok(Some(serialized_pat))
            } else {
                error!("Unexpected protocol buffer message received.");
                Err(VeracruzServerError::InvalidProtoBufMessage)
            }
        }

        fn get_enclave_cert(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
            info!("Requesting enclave certificate.");

            let message = serialize(&RuntimeManagerMessage::GetEnclaveCert).map_err(|e| {
                error!("Failed to serialize enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::EnclaveCert(buff) => {
                    info!("Enclave certificate retrieved.");
                    Ok(buff)
                },
                otherwise => {
                    error!("Unexpected response returned from enclave.  Received: {:?}.", otherwise);
                    VeracruzServerError::InvalidRuntimeManagerMessage(otherwise)
                }
            }
        }

        fn get_enclave_name(&mut self) -> Result<String, VeracruzServerError> {
            info!("Requesting enclave name.");

            let message = serialize(&RuntimeManagerMessage::GetEnclaveName).map_err(|e| {
                error!("Failed to serialize enclave name request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit enclave name request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to enclave name request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to enclave name request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::EnclaveName(name) => {
                    info!("Enclave certificate retrieved.");
                    Ok(name)
                },
                otherwise => {
                    error!("Unexpected response returned from enclave.  Received: {:?}.", otherwise);
                    VeracruzServerError::InvalidRuntimeManagerMessage(otherwise)
                }
            }
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
            info!("Requesting new TLS session.");

            let message = serialize(&RuntimeManagerMessage::NewTLSSession).map_err(|e| {
                error!("Failed to serialize new TLS session request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit new TLS session request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to new TLS session request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to new TLS session request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::TLSSession(session_id) => {
                    info!("Enclave started new TLS session with ID: {}.", session_id);
                    Ok(session_id)
                },
                otherwise => {
                    error!("Unexpected response returned from enclave.  Received: {:?}.", otherwise);
                    VeracruzServerError::InvalidRuntimeManagerMessage(otherwise)
                }
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            info!("Requesting close of TLS session with ID: {}.", session_id);

            let message = serialize(&RuntimeManagerMessage::CloseTLSSession(session_id)).map_err(|e| {
                error!("Failed to serialize TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("TLS session successfully closed.");
                    Ok(())
                },
                RuntimeManagerMessage::Status(status) => {
                    info!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    VeracruzServerError::NitroStatus(status)
                },
                otherwise => {
                    error!("Unexpected response returned from enclave.  Received: {:?}.", otherwise);
                    VeracruzServerError::InvalidRuntimeManagerMessage(otherwise)
                }
            }
        }

        fn tls_data(&mut self, session_id: u32, input: Vec<u8>) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            unimplemented!()
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Requesting shutdown of enclave.");

            let message = serialize(&RuntimeManagerMessage::).map_err(|e| {
                error!("Failed to serialize TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;
        }
    }

}