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

    use bincode::{deserialize, serialize};
    use log::{error, info};

    use std::{
        net::{Shutdown, TcpStream},
        process::{Child, Command},
        thread::sleep,
        time::Duration,
    };

    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use veracruz_utils::{
        platform::{
            linux::{LinuxRootEnclaveMessage, LinuxRootEnclaveResponse, receive_buffer, send_buffer},
            vm::{RuntimeManagerMessage, VMStatus},
        },
        policy::policy::Policy,
    };

    ////////////////////////////////////////////////////////////////////////////
    // Constants.
    ////////////////////////////////////////////////////////////////////////////

    /// Path to the pre-built Linux root enclave.
    const LINUX_ROOT_ENCLAVE_PATH: &'static str =
        "../linux-root-enclave/target/release/linux-root-enclave";
    /// Port to communicate with the Linux root enclave on.
    const LINUX_ROOT_ENCLAVE_PORT: &'static str = "4854";
    /// IP address to use when communicating with the Linux root enclave.
    const LINUX_ROOT_ENCLAVE_ADDRESS: &'static str = "127.0.0.1";
    /// IP address to use when communicating with the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_ADDRESS: &'static str = "127.0.0.1";
    /// Delay (in seconds) to use when spawning the Linux root enclave to
    /// ensure that everything is started before proceeding with communication
    /// between the server and enclave.
    const LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS: u64 = 2;

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Linux root enclave.
    pub struct VeracruzServerLinux {
        /// A handle to the Linux root enclave's process.
        linux_root_process: Child,
        /// The socket used to communicate with the Runtime Manager enclave.
        runtime_manager_socket: TcpStream,
        /// The socket used to communicate with the Linux Root enclave.
        linux_root_socket: TcpStream,
    }

    impl VeracruzServerLinux {
        /// Returns `Ok(true)` iff further TLS data can be read from the socket
        /// connecting the Veracruz server and the Linux root enclave.
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!("Failed to transmit request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
            })?;

            let received = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to request to check if TLS data can be read.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!("Failed to transmit request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
            })?;

            let received = receive_buffer(&self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to request for TLS data from Runtime Manager enclave.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
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
            info!("Dropping VeracruzServerLinux object, shutting down enclaves...");
            if let Err(error) = self.close() {
                error!(
                    "Failed to forcibly kill Runtime Manager and Linux Root enclave process.  Error produced: {:?}.",
                    error
                );
            }
        }
    }

    impl VeracruzServer for VeracruzServerLinux {
        /// Creates a new instance of the `VeracruzServerLinux` type.  To do
        /// this, we:
        ///
        /// 1. Spawn the Linux Root enclave,
        /// 2. Establish a socket connection between us and the Linux Root enclave,
        /// 3. Ask the Linux Root enclave to spawn a new Runtime Manager enclave,
        /// 4. Establish a socket connection to the Runtime Manager enclave on
        ///    the port assigned to us by the Linux Root enclave,
        /// 4. Send initializing messages to both enclaves.
        ///
        /// Note that this process can fail for a number of reasons, e.g. the
        /// enclaves may not be spawnable, socket connections can fail, the
        /// initialization processes of the two enclaves may fail, and so on.
        /// In those cases, an explicit error is returned.  Otherwise, we return
        /// `Ok(vsl)`.
        fn new(policy: &str) -> Result<Self, VeracruzServerError>
        where
            Self: Sized,
        {
            info!("Creating new Veracruz Server instance for Linux.");

            // TODO: add in dummy measurement and attestation token issuance here
            // which will use fields from the JSON policy file.
            let _policy_json = Policy::from_json(policy).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            info!("Successfully parsed JSON policy file.");

            info!(
                "Launching Linux Root enclave: {}.",
                LINUX_ROOT_ENCLAVE_PATH
            );

            let mut linux_root_process =
                Command::new(LINUX_ROOT_ENCLAVE_PATH).spawn().map_err(|e| {
                    error!(
                        "Failed to launch Linux Root enclave.  Error produced: {:?}.",
                        e
                    );
                    VeracruzServerError::IOError(e)
                })?;

            info!(
                "Linux Root enclave spawned.  Waiting {:?} seconds...",
                LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS
            );

            sleep(Duration::from_secs(LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS));

            let linux_root_enclave_address =
                format!("{}:{}", LINUX_ROOT_ENCLAVE_ADDRESS, LINUX_ROOT_ENCLAVE_PORT);

            info!(
                "Connecting to Linux Root enclave on {}.",
                linux_root_enclave_address
            );

            let mut linux_root_socket =
                TcpStream::connect(linux_root_enclave_address).map_err(|error| {
                    error!(
                        "Failed to connect to Linux Root enclave.  Error produced: {:?}.",
                        error
                    );
                    error!("Killing Linux Root enclave.");

                    // NB: we're in the process of failing here anyway, so we eat any error returned
                    // from this subprocess kill command.
                    let _result = linux_root_process.kill();

                    error
                })?;

            info!(
                "Now connected to Linux Root enclave on: {:?}.",
                linux_root_socket.peer_addr()
            );

            info!("Requesting spawning of new Runtime Enclave.");

            let spawn_message = serialize(&LinuxRootEnclaveMessage::SpawnNewApplicationEnclave).map_err(|e| {
                error!("Failed to serialize spawn request for new Runtime Manager enclave.  Error produced: {}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut linux_root_socket, &spawn_message).map_err(|e| {
                error!("Failed to transmit enclave spawn request to Linux Root enclave.  Error produced: {}.", e);

                VeracruzServerError::IOError(e)
            })?;

            info!("Spawn request sent.");

            let response_buffer = receive_buffer(&mut linux_root_socket).map_err(|e| {
                error!(
                    "Failed to receive response to enclave spawn request.  Error produced: {}.",
                    e
                );

                VeracruzServerError::IOError(e)
            })?;

            let response: LinuxRootEnclaveResponse = deserialize(&response_buffer).map_err(|e| {
                error!("Failed to deserialize response to enclave spawn request.  Error produced: {}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            info!("Response received.");

            let runtime_manager_port =
                if let LinuxRootEnclaveResponse::EnclaveSpawned(port) = response {
                    info!("Runtime Manager enclave assigned port: {}.", port);
                    port
                } else {
                    error!(
                        "Unexpected response received from Linux Root enclave.  Received: {:?}.",
                        response
                    );

                    return Err(VeracruzServerError::LinuxRootEnclaveUnexpectedResponse(
                        response,
                    ));
                };

            let runtime_manager_address = format!(
                "{}:{}",
                RUNTIME_MANAGER_ENCLAVE_ADDRESS, runtime_manager_port
            );

            info!(
                "Establishing connection with new Runtime Manager enclave on address: {}.",
                runtime_manager_address
            );

            let mut runtime_manager_socket = TcpStream::connect(&runtime_manager_address).map_err(|e| {
                error!("Failed to connect to Runtime Manager enclave at address {}.  Error produced: {}.", runtime_manager_address, e);

                VeracruzServerError::IOError(e)
            })?;

            info!(
                "Connected to Runtime Manager enclave at address {}.",
                runtime_manager_address
            );

            info!("Sending Initialize message.");

            let initialize_message = serialize(&RuntimeManagerMessage::Initialize(
                policy.to_string(),
            ))
            .map_err(|e| {
                error!(
                    "Failed to serialize Runtime Manager enclave initialization message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut runtime_manager_socket, &initialize_message).map_err(|e| {
                error!(
                    "Failed to transmit enclave initialization message.  Error produced: {:?}.",
                    e
                );
                e
            })?;

            info!("Message sent.");

            let init_buffer = receive_buffer(&runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to enclave initialization message.  Error produced: {:?}.", e);
                e
            })?;

            info!("Response received.");

            let status: RuntimeManagerMessage = deserialize(&init_buffer).map_err(|e| {
                error!("Failed to deserialize response to enclave initialization message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            return match status {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Enclaves successfully initialized.");

                    Ok(VeracruzServerLinux {
                        linux_root_process,
                        linux_root_socket,
                        runtime_manager_socket,
                    })
                }
                RuntimeManagerMessage::Status(status) => {
                    error!("Enclave sent status {:?}.", status);

                    Err(VeracruzServerError::VMStatus(status))
                }
                otherwise => {
                    error!("Enclave sent unexpected message: {:?}.", otherwise);

                    Err(VeracruzServerError::RuntimeManagerMessageStatus(otherwise))
                }
            };
        }

        fn proxy_psa_attestation_get_token(
            &mut self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError> {
            info!("Requesting proxy PSA attestation token.");

            let enclave_name = self.get_enclave_name()?;
            let enclave_cert = self.get_enclave_cert()?;

            let message = serialize(&LinuxRootEnclaveMessage::GetProxyAttestation(challenge, enclave_cert, enclave_name)).map_err(|e| {
                error!("Failed to serialize proxy PSA attestation token request.  Error produced: {:?}.", e);

                VeracruzServerError::BincodeError(*e)
            })?;

            send_buffer(&mut self.linux_root_socket, &message).map_err(|e| {
                error!("Failed to transmit proxy PSA attestation token request.  Error produced: {:?}.", e);


                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.linux_root_socket).map_err(|e| {
                error!("Failed to receive response to proxy PSA attestation token.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!("Failed to transmit enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to enclave certificate request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit enclave name request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to enclave name request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit new TLS session request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to new TLS session request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit TLS session close request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
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
                    Err(VeracruzServerError::VMStatus(status))
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!("Failed to send TLS data message.  Error produced: {:?}.", e);

                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&self.runtime_manager_socket).map_err(|e| {
                error!(
                    "Failed to receive response from TLS data message.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::IOError(e)
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

            while self.tls_data_needed(session_id)? {
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

            send_buffer(&mut self.runtime_manager_socket, &message).map_err(|e| {
                error!(
                    "Failed to transmit TLS session close request message.  Error produced: {:?}.",
                    e
                );
                VeracruzServerError::IOError(e)
            })?;

            let response = receive_buffer(&mut self.runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::IOError(e)
            })?;

            let message: RuntimeManagerMessage = deserialize(&response).map_err(|e| {
                error!("Failed to deserialize response to TLS session close request message.  Error produced: {:?}.", e);
                VeracruzServerError::BincodeError(*e)
            })?;

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    if let Err(e) = self.runtime_manager_socket.shutdown(Shutdown::Both) {
                        error!("Failed to shutdown Runtime Manager enclave socket.  Error produced: {:?}.", e);
                        return Err(VeracruzServerError::IOError(e));
                    }

                    // XXX: send shutdown message to Linux root enclave to kill runtime manager
                    // enclaves...

                    if let Err(e) = self.linux_root_socket.shutdown(Shutdown::Both) {
                        error!("Failed to shutdown Linux Root enclave socket.  Error produced: {:?}.", e);
                        return Err(VeracruzServerError::IOError(e));
                    }

                    if let Err(e) = self.linux_root_process.kill() {
                        error!(
                            "Failed to kill Linux Root enclave process.  Error produced: {:?}.",
                            e
                        );
                        return Err(VeracruzServerError::IOError(e));
                    }

                    info!("Enclave shutdown, and socket closed.");

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
