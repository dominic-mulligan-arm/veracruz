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

use crate::{VeracruzServer, VeracruzServerLinux};

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {

    use bincode::{deserialize, serialize};
    use log::{error, info};

    use std::{
        io::Write,
        net::{Shutdown, TcpStream},
        process::{Child, Command},
        thread::sleep,
        time::Duration,
    };

    use crate::VeracruzServerError::VeracruzSocketError;
    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use veracruz_utils::{
        receive_buffer, send_buffer, RuntimeManagerMessage, VMStatus, VeracruzPolicy,
    };

    /// Path to the pre-built Runtime Manager enclave.
    const RUNTIME_MANAGER_PATH: &'static str =
        "../runtime-manager/target/release/runtime_manager_enclave";
    /// Port to communicate with the Runtime Manager enclave on.
    const RUNTIME_MANAGER_PORT: &'static str = "5022";
    /// IP address to use when communicating with the Runtime Manager enclave.
    const RUNTIME_MANAGER_ADDRESS: &'static str = "127.0.0.1";
    /// Delay (in seconds) to use when spawning the Runtime Manager enclave to
    /// ensure that everything is started before proceeding with communication
    /// between the server and enclave.
    const RUNTIME_MANAGER_SPAWN_DELAY_SECONDS: u64 = 1;

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Runtime Manager Enclave.
    pub struct VeracruzServerLinux {
        /// A handle to the Runtime Manager Enclave's process.
        child_process: Child,
        /// The socket used to communicate with the Runtime Manager Enclave.
        socket: TcpStream,
    }

    impl VeracruzServerLinux {
        /// Returns `Ok(true)` iff further TLS data can be read from the socket
        /// connecting the Veracruz server and the Runtime Manager enclave.
        /// Returns `Ok(false)` iff no further TLS data can be read.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The request could not be serialized, or sent to the enclave.
        /// 2. The response could be not be received, or deserialized.
        /// 3. The response was received and deserialized correctly, but was of
        ///    an unexpected form.
        pub fn tls_data_needed(&mut self, session_id: u32) -> Result<bool, VeracruzServerError> {
            info!("Checking whether TLS data can be read from Runtime Manager enclave (with session: {}).", session_id);

            let message = serialize(&RuntimeManagerMessage::GetTLSDataNeeded(session_id)).map_err(|e| {
                error!("Failed to serialize request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let received = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message = deserialize(&received).map_err(|e| {
                error!("Failed to deserialize response to request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::TLSDataNeeded(response) => {
                    info!(
                        "Runtime Manager enclave can have further TLS data read: {}.",
                        response
                    );

                    Ok(response)
                }
                otherwise => {
                    error!(
                        "Runtime Manager enclave returned unexpected response.  Received: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        /// Reads TLS data from the Runtime Manager enclave.  Implicitly assumes
        /// that the Runtime Manager enclave has more data to be read.  Returns
        /// `Ok((alive_status, buffer))` if more TLS data could be read from the
        /// enclave, where `buffer` is a buffer of TLS data and `alive_status`
        /// captures the status of the TLS connection.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The TLS data request message cannot be serialized, or transmitted
        ///    to the enclave.
        /// 2. A response is not received back from the Enclave in response to
        ///    the message sent in (1) above, or the message cannot be
        ///    deserialized.
        /// 3. The Runtime Manager enclave sends back a message indicating that
        ///    it was not expecting further TLS data to be requested.
        pub fn read_tls_data(
            &mut self,
            session_id: u32,
        ) -> Result<(bool, Vec<u8>), VeracruzServerError> {
            info!(
                "Reading TLS data from Runtime Manager enclave (with session: {}).",
                session_id
            );

            let message = serialize(&RuntimeManagerMessage::GetTLSData(session_id)).map_err(|e| {
                error!("Failed to serialize request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let received = receive_buffer(&self.socket).map_err(|e| {
                error!("Failed to receive response to request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message = deserialize(&received).map_err(|e| {
                error!("Failed to deserialize response to request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::TLSData(buffer, alive) => {
                    info!("{} bytes of TLS data received from Runtime Manager enclave (alive status: {}).", buffer.len(), alive);

                    Ok((alive, buffer))
                }
                otherwise => {
                    error!("Unexpected reply received back from Runtime Manager enclave.  Recevied: {:?}.", otherwise);

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Trait implementations.
    ////////////////////////////////////////////////////////////////////////////

    /// An implementation of the `Drop` trait that forcibly kills the runtime
    /// manager enclave, and closes the socket used for communicating with it, when
    /// a `VeracruzServerLinux` struct is about to go out of scope.
    impl Drop for VeracruzServerLinux {
        #[inline]
        fn drop(&mut self) {
            if let Err(error) = self.close() {
                error!(
                    "Failed to forcibly kill runtime enclave process.  Error produced: {:?}.",
                    error
                );
            }
        }
    }

    impl VeracruzServer for VeracruzServerLinux {
        fn new(policy: &str) -> Result<Self, VeracruzServerError>
        where
            Self: Sized,
        {
            info!("Creating new Veracruz Server instance for Linux.");

            let policy_json = VeracruzPolicy::from_json(policy).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            info!("Successfully parsed JSON policy file.");

            info!(
                "Launching Runtime Manager enclave: {}.",
                RUNTIME_MANAGER_PATH
            );

            let mut child_process = Command::new(RUNTIME_MANAGER_PATH).spawn().map_err(|e| {
                error!(
                    "Failed to launch Runtime Manager enclave.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::IOError(e)
            })?;

            info!("Runtime Manager enclave spawned.");

            sleep(Duration::from_secs(RUNTIME_MANAGER_SPAWN_DELAY_SECONDS));

            let runtime_manager_address =
                format!("{}:{}", RUNTIME_MANAGER_ADDRESS, RUNTIME_MANAGER_PORT);

            info!(
                "Connecting to Runtime Manager enclave on {}.",
                runtime_manager_address
            );

            let mut socket = TcpStream::connect(runtime_manager_address).map_err(|error| {
                error!(
                    "Failed to connect to Runtime Manager enclave.  Error produced: {:?}.",
                    error
                );
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
                error!(
                    "Failed to transmit enclave initialization message.  Error produced: {:?}.",
                    e
                );
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
                RuntimeManagerMessage::Status(VMStatus::Success) => Ok(VeracruzServerLinux {
                    child_process,
                    socket,
                }),
                RuntimeManagerMessage::Status(status) => {
                    Err(VeracruzServerError::NitroStatus(status))
                }
                _otherwise => Err(VeracruzServerError::RuntimeManagerMessageStatus(message)),
            };
        }

        fn proxy_psa_attestation_get_token(
            &mut self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError> {
            info!("Requesting proxy PSA attestation token.");

            let message = serialize(&RuntimeManagerMessage::GetPSAAttestationToken(challenge)).map_err(|e| {
                error!("Failed to serialize proxy PSA attestation token request.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to transmit proxy PSA attestation token request.  Error produced: {:?}.", e);


                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&mut self.socket).map_err(|e| {
                error!("Failed to receive response to proxy PSA attestation token.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to proxy PSA attestation token.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::PSAAttestationToken(token, public_key, device_id) => {
                    info!("Proxy PSA attestation token received.  Token: {:?}.  Public key: {:?}.   Device ID: {}.", token, public_key, device_id);
                    Ok((token, public_key, device_id))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn plaintext_data(
            &mut self,
            data: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, VeracruzServerError> {
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
                )
                .map_err(|e| {
                    error!(
                        "Failed to serialize PSA proxy attestation token.  Error produced: {:?}.",
                        e
                    );
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
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn get_enclave_name(&mut self) -> Result<String, VeracruzServerError> {
            info!("Requesting enclave name.");

            let message = serialize(&RuntimeManagerMessage::GetEnclaveName).map_err(|e| {
                error!(
                    "Failed to serialize enclave name request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit enclave name request message.  Error produced: {:?}.",
                    e
                );
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
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
            info!("Requesting new TLS session.");

            let message = serialize(&RuntimeManagerMessage::NewTLSSession).map_err(|e| {
                error!(
                    "Failed to serialize new TLS session request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit new TLS session request message.  Error produced: {:?}.",
                    e
                );
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
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
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
                error!(
                    "Failed to transmit TLS session close request message.  Error produced: {:?}.",
                    e
                );
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
                }
                RuntimeManagerMessage::Status(status) => {
                    error!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    Err(VeracruzServerError::NitroStatus(status))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            info!(
                "Sending TLS data to runtime manager enclave (with session {}).",
                session_id
            );

            let message = serialize(&RuntimeManagerMessage::SendTLSData(session_id, input))
                .map_err(|e| {
                    error!(
                        "Failed to serialize TLS data message.  Error produced: {:?}.",
                        e
                    );

                    VeracruzServerError::BincodeError(*e)
                })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!("Failed to send TLS data message.  Error produced: {:?}.", e);

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let response = receive_buffer(&self.socket).map_err(|e| {
                error!(
                    "Failed to receive response from TLS data message.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzSocketError(e)
            })?;

            let message = deserialize(&response).map_err(|e| {
                error!(
                    "Failed to deserialize response to TLS data message.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Runtime Manager enclave successfully received TLS data.")
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!("Runtime Manager enclave failed to receive TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::VMStatus(otherwise));
                }
                otherwise => {
                    error!("Runtime Manager enclave produced an unexpected response to TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise));
                }
            }

            let mut active = false;
            let mut buffer = Vec::new();

            while self.tls_data_needed(session_id) {
                let (alive_status, received) = self.read_tls_data(session_id)?;

                active = alive_status;
                buffer.push(received);
            }

            if buffer.is_empty() {
                Ok((active, None))
            } else {
                Ok((active, Some(buffer)))
            }
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Requesting shutdown of enclave.");

            let message = serialize(&RuntimeManagerMessage::ResetEnclave).map_err(|e| {
                error!(
                    "Failed to serialize TLS session close request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit TLS session close request message.  Error produced: {:?}.",
                    e
                );
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
                    if let Err(e) = self.socket.shutdown(Shutdown::Both) {
                        error!("Failed to shutdown socket.  Error produced: {:?}.", e);
                        return Err(VeracruzServerError::IOError(e));
                    }

                    if let Err(e) = self.child_process.kill() {
                        error!(
                            "Failed to kill runtime enclave process.  Error produced: {:?}.",
                            e
                        );
                        return Err(VeracruzServerError::IOError(e));
                    }

                    Ok(true)
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!(
                        "Shutdown request resulted in unexpected status message.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::VMStatus(otherwise))
                }
                otherwise => {
                    error!("Shutdown request resulted in unexpected response from enclave.  Received: {:?}.", otherwise);
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }
    }
}
