//! Structs needed for Linux support, both inside and outside of the
//! trusted application.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

/// The Status value returned by the Linux application for operations
/// This is intended to be received as a bincode serialized
/// `LinuxRootApplicationMessage::Status`
#[derive(Serialize, Deserialize, Debug)]
pub enum LinuxStatus {
    /// The operation generating the message succeeded.
    Success,
    /// The operation generating the message failed.
    Fail,
    /// The requested operation is not yet implemented.
    Unimplemented,
}

////////////////////////////////////////////////////////////////////////////////
// Linux root enclave messages.
////////////////////////////////////////////////////////////////////////////////

/// Incoming messages to the Linux root enclave, instructing it to perform some
/// act.  These are sent serialized in `bincode` format.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
pub enum LinuxRootEnclaveMessage {
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
    /// Set the hash of the runtime manager to the supplied value.  This is
    /// **unsafe** but necessary for Linux, as we do not have a reliable way of
    /// obtaining a measurement of the runtime manager from the operating
    /// system.
    ///
    /// One way to fix this would be to write a kernel module that measures an
    /// application as it is loaded.
    SetRuntimeManagerHashHack(Vec<u8>),
    /// A request to shutdown the root enclave and any enclaves that it has
    /// launched.
    Shutdown,
    /// A request to spawn a new enclave containing an instance of Veracruz.
    SpawnNewApplicationEnclave,
}

/// Responses produced by the Linux root enclave after receiving and processing
/// a `LinuxRootEnclaveMessage` element, above.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
pub enum LinuxRootEnclaveResponse {
    /// The firmware version of the software executing inside the runtime
    /// enclave.  For Linux, this is mocked up.
    FirmwareVersion(String),
    /// The token produced by the native attestation process.
    NativeAttestationToken(Vec<u8>),
    /// The token produced by the proxy attestation process.
    ProxyAttestationToken(Vec<u8>),
    /// Acknowledgment that the root enclave is to shutdown.
    ShuttingDown,
    /// Acknowledgment that the runtime manager's hash has been set.
    HashSet,
    /// Indicates that a new Runtime Manager enclave has been spawned and this
    /// new enclave should be contacted on `localhost` using the designated
    /// port.
    EnclaveSpawned(u32),
}

////////////////////////////////////////////////////////////////////////////////
// I/O.
////////////////////////////////////////////////////////////////////////////////

/// Sends a `buffer` of data (by first transmitting an encoded length followed by
/// the data proper) to the file descriptor `fd`.
pub fn send_buffer<T>(mut fd: T, buffer: &[u8]) -> Result<(), std::io::Error>
where
    T: std::io::Write
{
    let len = buffer.len();

    // 1: Encode the data length and send it.
    {
        let mut buff = [0u8; 9];
        LittleEndian::write_u64(&mut buff, len as u64);

        let mut sent_bytes = 0;

        while sent_bytes < 9 {
            sent_bytes += fd.write(&buff[sent_bytes..9])?;
        }
    }

    // 2. Send the data proper.
    {
        let mut sent_bytes = 0;

        while sent_bytes < len {
            sent_bytes += fd.write(&buffer[sent_bytes..len])?;
        }
    }

    Ok(())
}

/// Reads a buffer of data from a file descriptor `fd` by first reading a length
/// of data, followed by the data proper.
pub fn receive_buffer<T>(mut fd: T) -> Result<Vec<u8>, std::io::Error>
where
    T: std::io::Read
{
    // 1. First read and decode the length of the data proper.
    let length = {
        let mut buff = [0u8; 9];
        let mut received_bytes = 0;

        while received_bytes < 9 {
            received_bytes += fd.read(&mut buff[received_bytes..9])?;
        }

        LittleEndian::read_u64(&buff) as usize
    };

    // 2. Next, read the data proper.
    let mut buffer = vec![0u8; length];

    {
        let mut received_bytes = 0;

        while received_bytes < length {
            received_bytes += fd.read(&mut buffer[received_bytes..length])?;
        }
    }

    Ok(buffer)
}
