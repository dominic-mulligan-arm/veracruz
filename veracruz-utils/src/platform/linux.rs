//! Structs needed for Linux support, both inside and outside of the
//! trusted application.
//!
//! ## Authors
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

        while sent_bytes < len {
            sent_bytes += fd.write(&buff[sent_bytes..len])?;
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
