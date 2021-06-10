//! The root enclave (read: application) for Linux
//!
//! Interprets command messages sent over a TCP socket, acts on them, then sends
//! responses back.  Command messages consist of:
//!
//!  - Requests to shutdown the root enclave, which terminates the listening
//!    loop,
//!  - Requests to obtain the hash of the Linux root enclave server,
//!  - Requests for proxy and native attestation tokens,
//!  - A **hack** message which sets the hash of the runtime manager enclave to
//!    a given value for attestation purposes.  This is because the operating
//!    system (Linux in this case) provides no way of reliably measuring a
//!    loaded program.
//!
//! **NOTE**: the attestation flow defined in this file is completely insecure,
//! and can probably never be made really secure.
//!
//! As a result, we've cut a few corners implementing this (e.g. with the
//! pre-generated `LINUX_ROOT_ENCLAVE_PRIVATE_KEY` embedded in the source below)
//! which need fixing if they are to be used in a security-sensitive setting.
//!
//! See the comparable Intel SGX or AWS Nitro flows for a secure and reliable
//! implementation of attestation for Veracruz.
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
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, t_cose_sign1_get_verification_pubkey,
};
use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};
use std::process::Child;
use std::{
    env::current_exe,
    fs::File,
    io::{Error as IOError, Read},
    net::TcpListener,
    os::unix::io::AsRawFd,
    process::Command,
    sync::{atomic::Ordering, Mutex},
};
use veracruz_utils::platform::linux::{
    receive_buffer, send_buffer, LinuxRootEnclaveMessage, LinuxRootEnclaveResponse,
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that "0.0.0.0" means that we listen on
/// all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// Incoming port to listen on.
const INCOMING_PORT: &'static str = "5021";
/// Path to the Runtime Manager binary.
const RUNTIME_MANAGER_ENCLAVE_PATH: &'static str =
    "../runtime-manager-enclave/target/release/runtime-manager-enclave";

lazy_static! {
    static ref DEVICE_PUBLIC_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref DEVICE_PRIVATE_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref DEVICE_ID: Mutex<Option<i32>> = Mutex::new(None);
    /// This stores the hash of the runtime manager.  Note that, in the current
    /// implementation of this flow for Linux, this is provided to us by code
    /// interacting with us, not by the operating system which provides no
    /// reliable way of obtaining a measurement.
    static ref RUNTIME_MANAGER_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    /// NOTE: this is hardcoded into the root enclave binary, which is
    /// completely insecure.  A better way of doing this would be to generate a
    /// key at initialization time and share this with the proxy attestation
    /// service.  However, this Linux flow is a dummy attestation flow that has
    /// limited value, anyway, given that Linux processes are not secured
    /// against a malicious operating system.  We therefore use this approach
    /// instead, at least for the time being.
    static ref LINUX_ROOT_ENCLAVE_PRIVATE_KEY: Vec<u8> = vec![
        0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
        0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x5, 0x76, 0xa1, 0x44,
    ];
    /// Handles to all of the processes of the enclaves launched by the root
    /// enclave.
    static ref LAUNCHED_ENCLAVES: Mutex<Vec<Child>> = Mutex::new(Vec::new());
    /// The next port to use to communicate with a newly-launched enclave.
    static ref ENCLAVE_PORT: AtomicU32 = AtomicU32::new(6000);
}

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

/// Captures all of the different errors that can be produced when trying to
/// listen on, and subsequently process, all of the root enclave messages.
#[derive(Debug, Error)]
enum LinuxRootEnclaveError {
    #[error(display = "PSA attestation process failed.")]
    /// Some aspect of the attestation process failed to complete correctly.
    AttestationError,
    #[error(display = "Cryptography key generation process failed.")]
    /// Some aspect of the key generation process failed to complete correctly.
    CryptographyError,
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
    #[error(display = "An internal invariant failed.")]
    /// An internal invariant failed, i.e. something that was not initialized that
    /// should have been.
    InvariantFailed,
    #[error(display = "A lock on a global object could not be obtained.")]
    /// A lock on a global object could not be obtained.
    LockingError,
    #[error(display = "Failed to set socket options.  Error produced: {}.", _0)]
    /// We were unable to set suitable options on the TCP socket.
    SetSocketOptionsError(NixError),
    #[error(display = "Socket IO error.  Error produced: {}.", _0)]
    /// There was an error either opening, or working with, sockets.
    SocketError(IOError),
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

    info!("Read {:?} bytes from binary.", length);

    let measurement = digest(&SHA256, &buffer).as_ref().to_vec();

    info!("Measurement computed: {}.", encode(&measurement));

    Ok(measurement)
}

/// Returns the measurement of the Runtime Manager binary.
fn get_runtime_manager_hash() -> Result<Vec<u8>, LinuxRootEnclaveError> {
    let runtime_manager_hash = RUNTIME_MANAGER_HASH.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on RUNTIME_MANAGER_HASH.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    match &*runtime_manager_hash {
        Some(hash) => Ok(hash.clone()),
        None => {
            error!("No runtime manager hash available.");
            Err(LinuxRootEnclaveError::AttestationError)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Responses to message stimuli.
////////////////////////////////////////////////////////////////////////////////

/// Launches a new instance of the Runtime Manager enclave.  Assigns a fresh
/// port number to the enclave and returns it if the enclave is successfully
/// launched.  Returns `Err(err)` with a suitable error if the Runtime Manager
/// enclave cannot be launched, or if the internal database of launched enclaves
/// cannot be locked.
fn launch_new_runtime_manager_enclave() -> Result<u32, LinuxRootEnclaveError> {
    info!("Launching new Runtime Manager enclave.");

    let command = Command::new(RUNTIME_MANAGER_ENCLAVE_PATH)
        .spawn()
        .map_err(|e| {
            error!(
                "Failed to launch Runtime Manager enclave.  Error produced: {}.",
                e
            );

            LinuxRootEnclaveError::GeneralIOError(e)
        })?;

    info!("New Runtime Manager enclave launched.");

    let mut children = LAUNCHED_ENCLAVES.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on LAUNCHED_ENCLAVES.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    children.push(command);

    let port = ENCLAVE_PORT.fetch_add(1u32, Ordering::SeqCst);

    info!("Assigning port {} to new enclave.", port);

    Ok(port)
}

/// Kills all of the enclaves that the Linux root enclave has spawned.  If any
/// process cannot be killed then this is logged on the error logger but no
/// further error is produced as we are in the process of exiting when this
/// function is called, anyway.
fn kill_all_enclaves() -> Result<(), LinuxRootEnclaveError> {
    info!("Killing all launched Runtime Manager enclaves.");

    let mut children = LAUNCHED_ENCLAVES.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on LAUNCHED_ENCLAVES.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    for child in children.iter_mut() {
        info!("Killing process {}.", child.id());

        child.kill().map_err(|e| {
            error!("Failed to kill process {}.", child.id());
        })
    }

    Ok(())
}

/// Returns the version of the trusted runtime's software stack.  Note that on
/// Linux this is mocked up, as the attestation process is completely insecure.
#[inline]
fn get_firmware_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Computes a native PSA attestation token from a challenge value, `challenge`,
/// and the device ID.
fn get_native_attestation_token(
    challenge: Vec<u8>,
    device_id: i32,
) -> Result<Vec<u8>, LinuxRootEnclaveError> {
    info!("Obtaining native attestation token.");

    /* 1. Load the root enclave private key. */

    let mut root_key_handle = 0;

    let status = unsafe {
        psa_initial_attest_load_key(
            LINUX_ROOT_ENCLAVE_PRIVATE_KEY.as_ptr(),
            LINUX_ROOT_ENCLAVE_PRIVATE_KEY.len() as u64,
            &mut root_key_handle,
        )
    };

    if status != 0 {
        error!("Failed to load Linux root enclave private key.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    /* 2. Save the device ID. */

    let mut device_id_lock = DEVICE_ID.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_ID.");
        LinuxRootEnclaveError::LockingError
    })?;

    *device_id_lock = Some(device_id);

    /* 3. Hash the device's public key using SHA-256. */

    let device_public_key = DEVICE_PUBLIC_KEY.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_PUBLIC_KEY.");
        LinuxRootEnclaveError::LockingError
    })?;

    let device_public_key = match &*device_public_key {
        Some(key) => key.clone(),
        None => {
            error!("DEVICE_PUBLIC_KEY has not been initialized.");
            return Err(LinuxRootEnclaveError::InvariantFailed);
        }
    };

    let device_public_key_hash = digest(&SHA256, &device_public_key).as_ref().to_vec();

    /* 4. Obtain the hash of the Linux root enclave (i.e. this executable). */

    let root_enclave_hash = get_root_enclave_hash()?;

    /* 5. Generate the token. */

    let mut token_buffer = Vec::with_capacity(1024);
    let mut token_size: u64 = 0;

    let status = unsafe {
        psa_initial_attest_get_token(
            root_enclave_hash.as_ptr() as *const u8,
            root_enclave_hash.len() as u64,
            device_public_key_hash.as_ptr() as *const u8,
            device_public_key_hash.len() as u64,
            std::ptr::null() as *const i8,
            0,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token_buffer.as_mut_ptr() as *mut u8,
            token_buffer.capacity() as u64,
            &mut token_size as *mut u64,
        )
    };

    if status != 0 {
        error!("Failed to generate a PSA attestation token.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    /* 6. Tidy up. */

    unsafe {
        token_buffer.set_len(token_size as usize);
    };

    info!("Successfully produced PSA attestation token.");

    Ok(token_buffer)
}

/// Computes a proxy PSA attestation token from a challenge value, `challenge`,
/// an encoding of the enclave's certificate, `certificate`, and the name of the
/// enclave, `enclave_name`.
fn get_proxy_attestation_token(
    challenge: Vec<u8>,
    certificate: Vec<u8>,
    enclave_name: String,
) -> Result<Vec<u8>, LinuxRootEnclaveError> {
    info!("Obtaining proxy attestation token.");

    /* 1. Obtain the device's private key. */

    let device_private_key = DEVICE_PRIVATE_KEY.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_PRIVATE_KEY.");
        LinuxRootEnclaveError::LockingError
    })?;

    let device_private_key = match &*device_private_key {
        Some(key) => key.clone(),
        None => {
            error!("DEVICE_PRIVATE_KEY has not been initialized.");
            return Err(LinuxRootEnclaveError::InvariantFailed);
        }
    };

    let mut device_key_handle = 0;

    let status = unsafe {
        psa_initial_attest_load_key(
            device_private_key.as_ptr(),
            device_private_key.len() as u64,
            &mut device_key_handle,
        )
    };

    if status != 0 {
        error!("Failed to load Linux root enclave private key.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    /* 2. Obtain the hash of the runtime manager. */

    let runtime_manager_hash = get_runtime_manager_hash()?;

    /* 3. Get the enclave certificate. */

    let certificate_hash = digest(&SHA256, &certificate);
    let enclave_name_bytes = enclave_name.as_bytes();

    /* 4. Generate the proxy attestation token. */

    let mut token: Vec<u8> = Vec::with_capacity(2048);
    let mut token_len: u64 = 0;

    let status = unsafe {
        psa_initial_attest_get_token(
            runtime_manager_hash.as_ptr() as *const u8,
            runtime_manager_hash.len() as u64,
            certificate_hash.as_ref().as_ptr() as *const u8,
            certificate_hash.as_ref().len() as u64,
            enclave_name_bytes.as_ptr() as *const i8,
            enclave_name_bytes.len() as u64,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            2048,
            &mut token_len as *mut u64,
        )
    };

    if status != 0 {
        error!("Failed to generate proxy attestation token.");
        return Err(LinuxRootEnclaveError::AttestationError);
    }

    /* 5. Tidy up. */

    unsafe {
        token.set_len(token_len as usize);
    };

    info!("Proxy PSA attestation token generated.");

    Ok(token)
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Generates a public/private key pair for the root enclave to use as part of
/// the attestation process.
fn generate_key_pairs() -> Result<(), LinuxRootEnclaveError> {
    info!("Generating device key pairs.");

    /* 1. Generate the private key. */

    let device_private_key = {
        let rng = SystemRandom::new();
        let pkcs_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_e| {
                error!("Failed to generate PKCS key-pair.");
                LinuxRootEnclaveError::CryptographyError
            })?;
        pkcs_bytes.as_ref()[38..70].to_vec()
    };

    /* 2. Register it in the global variable. */

    let mut private_key_lock = DEVICE_PRIVATE_KEY.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_PRIVATE_KEY.");
        LinuxRootEnclaveError::LockingError
    })?;

    *private_key_lock = Some(device_private_key.clone());

    /* 3. Obtain the public key.  To obtain a correctly-formatted public key we
         use a bit of a hack, storing the key and then retrieving it.
    */

    let mut device_key_handle = 0;

    let status = unsafe {
        psa_initial_attest_load_key(
            device_private_key.as_ptr(),
            device_private_key.len() as u64,
            &mut device_key_handle,
        )
    };

    if status != 0 {
        error!("Failed to load device private key.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    let mut public_key = Vec::with_capacity(128);
    let mut public_key_size: u64 = 0;

    let status = unsafe {
        t_cose_sign1_get_verification_pubkey(
            device_key_handle,
            public_key.as_mut_ptr() as *mut u8,
            public_key.capacity() as u64,
            &mut public_key_size as *mut u64,
        )
    };

    if status != 0 {
        error!("Failed to retrieve public key.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    /* 4. Trim the buffer holding the key to size. */

    unsafe { public_key.set_len(public_key_size as usize) };

    /* 5. Register it in a global variable. */

    let mut public_key_lock = DEVICE_PUBLIC_KEY.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_PUBLIC_KEY.");
        LinuxRootEnclaveError::LockingError
    })?;

    *public_key_lock = Some(public_key);

    info!("Device public and private key-pair generated successfully.");

    Ok(())
}

/// Entry point for the root enclave.  This sets up a TCP listener and processes
/// messages, deserializing them using Bincode.  Can fail for a variety of
/// reasons, all of which are captured in the `LinuxRootEnclaveError` type.
fn entry_point() -> Result<(), LinuxRootEnclaveError> {
    info!("Linux root enclave initializing.");

    generate_key_pairs()?;

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

        info!("Received message: {}.", received_message);

        let response = match received_message {
            LinuxRootEnclaveMessage::SpawnNewApplicationEnclave => {
                info!("Spawning new application enclave.");

                Ok(LinuxRootEnclaveResponse::EnclaveSpawned(
                    launch_new_runtime_manager_enclave()?,
                ))
            }
            LinuxRootEnclaveMessage::GetFirmwareVersion => {
                info!("Computing firmware version.");

                Ok(LinuxRootEnclaveResponse::FirmwareVersion(
                    get_firmware_version(),
                ))
            }
            LinuxRootEnclaveMessage::SetRuntimeManagerHashHack(hash) => {
                info!("Setting Runtime Manager hash to {:?}.", hash);

                let mut runtime_manager_hash = RUNTIME_MANAGER_HASH.lock().map_err(|e| {
                    error!(
                        "Failed to obtain lock on RUNTIME_MANAGER_HASH.  Error produced: {}.",
                        e
                    );

                    LinuxRootEnclaveError::LockingError
                })?;

                *runtime_manager_hash = Some(hash);

                Ok(LinuxRootEnclaveResponse::HashSet)
            }
            LinuxRootEnclaveMessage::Shutdown => {
                info!("Shutting down the Linux root enclave.");

                shutdown = true;
                kill_all_enclaves()?;

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

        info!("Producing response: {}.", response);

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
