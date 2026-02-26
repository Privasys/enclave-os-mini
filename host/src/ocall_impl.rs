// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall implementation – with the SPSC queue architecture, only ONE
//! OCALL remains: `ocall_notify()`.
//!
//! This function is called by the enclave after writing a request to the
//! shared-memory enc_to_host queue. It serves as a lightweight wake-up
//! signal for the host RPC dispatcher.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::OnceLock;

static NOTIFY_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Set the shared notify/shutdown flag (called from main before enclave starts).
pub fn set_notify_flag(flag: Arc<AtomicBool>) {
    let _ = NOTIFY_FLAG.set(flag);
}

/// The single OCALL: notification from enclave that a request is ready.
///
/// The actual data transfer happens through the shared-memory SPSC queue,
/// so this function carries no payload. It merely ensures the host
/// dispatcher thread is awake. The dispatcher's spin-backoff loop will
/// pick up the message from the queue.
#[no_mangle]
pub extern "C" fn ocall_notify() {
    // The dispatcher polls the queue with backoff. If it's sleeping
    // (1ms backoff), this OCALL naturally wakes the thread because the
    // enclave's OCALL itself causes a context switch back to host code
    // on the same TCS thread pool.
    //
    // For more aggressive wake-up, we could use a condvar or eventfd here.
    // The current spin-backoff with max 1ms sleep is sufficient.
}

// `sgx_oc_cpuidex` OCALL is provided by Intel's `libsgx_urts.so`, which
// the host links.  No Rust implementation needed — the untrusted runtime
// already executes CPUID on behalf of the enclave.
