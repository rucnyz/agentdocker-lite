//! QMP (QEMU Monitor Protocol) client.
//!
//! Connects to a QEMU QMP Unix socket, negotiates capabilities,
//! sends a JSON command, and returns the response.  Host-side
//! native Rust implementation callable directly from Python via
//! `PyO3`.  Guest-side command execution uses QGA (QEMU Guest Agent)
//! via `vm.py`, not this module.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Send a QMP command and return the JSON response string.
///
/// Protocol flow:
/// 1. Connect to Unix socket
/// 2. Read greeting (contains `"QMP"` key)
/// 3. Send `{"execute":"qmp_capabilities"}`
/// 4. Read capabilities response
/// 5. Send the user command
/// 6. Skip async events, return the first line containing `"return"` or `"error"`
pub fn qmp_send(socket_path: &str, command_json: &str, timeout_secs: u64) -> io::Result<String> {
    let stream = UnixStream::connect(socket_path)?;
    let timeout = Duration::from_secs(timeout_secs);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    // 1. Read QMP greeting
    let mut line = String::new();
    reader.read_line(&mut line)?;
    // Greeting should contain "QMP"
    if !line.contains("\"QMP\"") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected QMP greeting: {}", line.trim()),
        ));
    }

    // 2. Send qmp_capabilities
    writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    writer.flush()?;

    // 3. Read capabilities response
    line.clear();
    reader.read_line(&mut line)?;
    // Should contain "return"
    if !line.contains("\"return\"") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("qmp_capabilities failed: {}", line.trim()),
        ));
    }

    // 4. Send user command
    writer.write_all(command_json.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    // 5. Read response, skip async events
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "QMP connection closed before response",
            ));
        }
        let trimmed = line.trim();
        if trimmed.contains("\"return\"") || trimmed.contains("\"error\"") {
            return Ok(trimmed.to_string());
        }
        // else: async event (e.g. RESUME), skip
    }
}
