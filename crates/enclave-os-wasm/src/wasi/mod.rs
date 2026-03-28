// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Custom WASI host-function implementations backed by the enclave OS.
//!
//! Standard `wasmtime-wasi` calls real OS syscalls (read, write, mmap, …)
//! which are unavailable inside SGX.  This module provides replacement
//! implementations that route through enclave OS primitives:
//!
//! | WASI interface              | Enclave OS backing                       |
//! |-----------------------------|------------------------------------------|
//! | `wasi:random/random`        | RDRAND via `getrandom` (sgx_read_rand)   |
//! | `wasi:clocks/wall-clock`    | OCALL `get_current_time()`               |
//! | `wasi:clocks/monotonic`     | OCALL `get_current_time()` (best-effort) |
//! | `wasi:cli/environment`      | Controlled env vars from AppContext      |
//! | `wasi:cli/stdout` / `stderr`| Streamed to enclave log via OCALL        |
//! | `wasi:cli/stdin`            | In-memory buffer via input-stream        |
//! | `wasi:io/streams`           | Resource-backed stream I/O               |
//! | `wasi:io/poll`              | Always-ready synchronous pollables       |
//! | `wasi:sockets/tcp`          | OCALL `net_tcp_*` wrappers               |
//! | `wasi:filesystem/*`         | Sealed KV store via OCALL `kv_*`         |

pub mod cli;
pub mod filesystem;
pub mod io;
pub mod sockets;

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;

use crate::enclave_sdk::KeyStore;
use enclave_os_kvstore::SealedKvStore;
use enclave_os_common::types::AEAD_KEY_SIZE;

// ---------------------------------------------------------------------------
//  Resource marker types (phantom — only used for Resource<T> type tagging)
// ---------------------------------------------------------------------------

/// Marker for `wasi:io/error.error` resource.
pub struct IoErrorRes;

/// Marker for `wasi:io/poll.pollable` resource.
pub struct PollableRes;

/// Marker for `wasi:io/streams.input-stream` resource.
pub struct InputStreamRes;

/// Marker for `wasi:io/streams.output-stream` resource.
pub struct OutputStreamRes;

/// Marker for `wasi:sockets/tcp.tcp-socket` resource.
pub struct TcpSocketRes;

/// Marker for `wasi:sockets/network.network` resource.
pub struct NetworkRes;

/// Marker for `wasi:filesystem/types.descriptor` resource.
pub struct DescriptorRes;

/// Marker for `wasi:filesystem/types.directory-entry-stream` resource.
pub struct DirEntryStreamRes;

// ---------------------------------------------------------------------------
//  Resource backing data
// ---------------------------------------------------------------------------

/// Where an output-stream delivers its bytes.
#[derive(Clone, Copy, Debug)]
pub enum OutputStreamKind {
    Stdout,
    Stderr,
    TcpSocket(i32),
    Null,
}

/// Where an input-stream reads its bytes from.
#[derive(Clone, Debug)]
pub enum InputStreamKind {
    Stdin,
    TcpSocket(i32),
    /// In-memory buffer with current read position.
    Buffer { data: Vec<u8>, pos: usize },
    Empty,
}

/// Per-socket state.
pub struct TcpSocketState {
    pub fd: Option<i32>,
    pub bound: bool,
    pub listening: bool,
    pub connected: bool,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl TcpSocketState {
    pub fn new() -> Self {
        Self {
            fd: None,
            bound: false,
            listening: false,
            connected: false,
            local_port: 0,
            remote_host: String::new(),
            remote_port: 0,
        }
    }
}

/// Filesystem descriptor (file or directory backed by KV store).
pub enum FsDescriptor {
    /// A directory is a KV-prefix namespace.
    Directory { prefix: String },
    /// A file is a single KV entry with an in-memory buffer.
    File {
        key: String,
        buf: Vec<u8>,
        pos: usize,
        dirty: bool,
    },
}

/// A single directory entry for iteration.
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// State for iterating directory entries.
pub struct DirEntryStreamState {
    pub entries: Vec<DirEntry>,
    pub pos: usize,
}

// ---------------------------------------------------------------------------
//  AppContext — per-WASM-instance state visible to WASI host functions
// ---------------------------------------------------------------------------

/// Per-app execution context.
///
/// Each [`wasmtime::Store`] owns an `AppContext` that accumulates I/O from
/// the guest and provides environment data.  Resource handles (output
/// streams, sockets, etc.) are tracked in BTreeMaps keyed by a
/// monotonically-increasing `u32` representation value.
pub struct AppContext {
    /// KV table name for this app's data.
    ///
    /// Each app gets its own RocksDB column family (table), enabling
    /// per-app key iteration and complete data isolation.
    /// Format: `"app:<name>"` — e.g. `"app:my-dapp"`.
    pub app_table: String,

    /// App name for log message prefixing.
    pub app_name: String,
    /// Line buffer for stdout (partial lines accumulate here).
    stdout_buf: Vec<u8>,
    /// Line buffer for stderr (partial lines accumulate here).
    stderr_buf: Vec<u8>,
    /// Input bytes available to the guest's stdin.
    pub stdin: Vec<u8>,
    /// Current read position in stdin.
    pub stdin_pos: usize,
    /// Environment variables visible to the guest.
    pub env_vars: Vec<(String, String)>,
    /// Command-line arguments visible to the guest.
    pub args: Vec<String>,

    // ── Enclave SDK state ──────────────────────────────────────────
    /// In-memory crypto key store (Enclave OS SDK).
    pub keystore: KeyStore,
    /// Encrypted KV store for WASI filesystem and key persistence.
    /// Routes all host-side storage through AES-256-GCM encryption.
    pub sealed_kv: SealedKvStore,

    // ── Caller identity (set per-request before WASM dispatch) ────
    /// Authenticated caller's user ID (FIDO2 user_handle or OIDC sub).
    /// `None` when the function has a public policy or no auth was provided.
    pub caller_id: Option<String>,
    /// Authenticated caller's roles (from enclave role store or OIDC claims).
    pub caller_roles: Vec<String>,

    // ── Resource tracking ──────────────────────────────────────────
    /// Output-stream rep → kind.
    pub(crate) output_streams: BTreeMap<u32, OutputStreamKind>,
    /// Input-stream rep → kind.
    pub(crate) input_streams: BTreeMap<u32, InputStreamKind>,
    /// TCP socket rep → state.
    pub(crate) tcp_sockets: BTreeMap<u32, TcpSocketState>,
    /// Filesystem descriptor rep → data.
    pub(crate) fs_descriptors: BTreeMap<u32, FsDescriptor>,
    /// Directory-entry-stream rep → iterator state.
    pub(crate) dir_entry_streams: BTreeMap<u32, DirEntryStreamState>,
    /// IO error rep → debug message.
    pub(crate) errors: BTreeMap<u32, String>,

    /// Next resource representation value (monotonically increasing).
    next_rep: u32,
}

impl AppContext {
    /// Create a new empty app context.
    pub fn new() -> Self {
        Self::with_app("default", [0u8; AEAD_KEY_SIZE])
    }

    /// Create an app context scoped to a specific app.
    ///
    /// All KV store operations (filesystem, key persistence) will use
    /// the `app:<app_name>` table (RocksDB column family) for isolation.
    pub fn with_app(app_name: &str, master_key: [u8; AEAD_KEY_SIZE]) -> Self {
        Self {
            app_table: format!("app:{}", app_name),
            app_name: app_name.to_string(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            stdin: Vec::new(),
            stdin_pos: 0,
            env_vars: Vec::new(),
            args: Vec::new(),
            keystore: KeyStore::new(),
            sealed_kv: SealedKvStore::from_master_key_with_table(master_key, format!("app:{}", app_name).as_bytes()),
            caller_id: None,
            caller_roles: Vec::new(),
            output_streams: BTreeMap::new(),
            input_streams: BTreeMap::new(),
            tcp_sockets: BTreeMap::new(),
            fs_descriptors: BTreeMap::new(),
            dir_entry_streams: BTreeMap::new(),
            errors: BTreeMap::new(),
            next_rep: 1, // start at 1 (0 is often "null")
        }
    }

    /// Create an app context with pre-set environment variables.
    pub fn with_env(env_vars: Vec<(String, String)>) -> Self {
        let mut state = Self::new();
        state.env_vars = env_vars;
        state
    }

    /// Allocate a fresh resource representation value.
    pub fn alloc_rep(&mut self) -> u32 {
        let rep = self.next_rep;
        self.next_rep = self.next_rep.wrapping_add(1);
        rep
    }

    /// Flush any remaining partial line in stdout to the enclave log.
    pub fn flush_stdout(&mut self) {
        if !self.stdout_buf.is_empty() {
            if let Ok(s) = core::str::from_utf8(&self.stdout_buf) {
                enclave_os_common::enclave_log_info!("[wasm:{}] {}", self.app_name, s);
            }
            self.stdout_buf.clear();
        }
    }

    /// Flush any remaining partial line in stderr to the enclave log.
    pub fn flush_stderr(&mut self) {
        if !self.stderr_buf.is_empty() {
            if let Ok(s) = core::str::from_utf8(&self.stderr_buf) {
                enclave_os_common::enclave_log_error!("[wasm:{}] {}", self.app_name, s);
            }
            self.stderr_buf.clear();
        }
    }

    /// Flush all remaining partial lines (call at end of WASM invocation).
    pub fn flush_logs(&mut self) {
        self.flush_stdout();
        self.flush_stderr();
    }

    /// Line-buffered forward of data to the enclave log.
    ///
    /// Complete lines (terminated by `\n`) are forwarded immediately.
    /// Partial trailing data is held in the buffer until the next write
    /// or [`flush_logs()`](Self::flush_logs).
    fn forward_to_log(buf: &mut Vec<u8>, app_name: &str, data: &[u8], is_stderr: bool) {
        buf.extend_from_slice(data);
        // Emit every complete line.
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            if let Ok(line) = core::str::from_utf8(&buf[..pos]) {
                if is_stderr {
                    enclave_os_common::enclave_log_error!("[wasm:{}] {}", app_name, line);
                } else {
                    enclave_os_common::enclave_log_info!("[wasm:{}] {}", app_name, line);
                }
            }
            buf.drain(..=pos);
        }
    }

    /// Write to an output stream identified by rep.
    ///
    /// For stdout/stderr, complete lines are streamed to the enclave log
    /// immediately.  Partial lines accumulate until the next `\n`.
    pub fn write_stream(&mut self, rep: u32, data: &[u8]) -> Result<(), &'static str> {
        let kind = match self.output_streams.get(&rep) {
            Some(k) => *k,
            None => return Err("closed"),
        };
        match kind {
            OutputStreamKind::Stdout => {
                Self::forward_to_log(&mut self.stdout_buf, &self.app_name, data, false);
            }
            OutputStreamKind::Stderr => {
                Self::forward_to_log(&mut self.stderr_buf, &self.app_name, data, true);
            }
            OutputStreamKind::TcpSocket(fd) => {
                if let Err(_) = enclave_os_common::ocall::net_send(fd, data) {
                    return Err("last-operation-failed");
                }
            }
            OutputStreamKind::Null => { /* discard */ }
        }
        Ok(())
    }

    /// Read from an input stream identified by rep.
    ///
    /// Returns the bytes read (may be empty if no data available).
    pub fn read_stream(&mut self, rep: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        let kind = match self.input_streams.get_mut(&rep) {
            Some(k) => k,
            None => return Err("closed"),
        };
        match kind {
            InputStreamKind::Stdin => {
                let avail = self.stdin.len() - self.stdin_pos;
                let take = avail.min(max_len);
                let data = self.stdin[self.stdin_pos..self.stdin_pos + take].to_vec();
                self.stdin_pos += take;
                Ok(data)
            }
            InputStreamKind::TcpSocket(fd) => {
                let fd = *fd;
                let mut buf = vec![0u8; max_len.min(65536)];
                match enclave_os_common::ocall::net_recv(fd, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(buf)
                    }
                    Err(_) => Err("last-operation-failed"),
                }
            }
            InputStreamKind::Buffer { data, pos } => {
                let avail = data.len() - *pos;
                let take = avail.min(max_len);
                let result = data[*pos..*pos + take].to_vec();
                *pos += take;
                Ok(result)
            }
            InputStreamKind::Empty => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
//  add_wasi_to_linker — register all WASI host function implementations
// ---------------------------------------------------------------------------

/// Register all WASI host function implementations in the given [`Linker`].
///
/// This populates the standard WASI namespaces so that WASM components
/// targeting `wasi:cli/run@0.2.0` (wasip2) can be instantiated.
pub fn add_wasi_to_linker(
    linker: &mut Linker<AppContext>,
) -> Result<(), wasmtime::Error> {
    io::add_to_linker(linker)?;
    cli::add_to_linker(linker)?;
    sockets::add_to_linker(linker)?;
    filesystem::add_to_linker(linker)?;
    Ok(())
}
