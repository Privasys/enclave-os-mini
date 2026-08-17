// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/ledger@0.1.0` — the replicated, authenticated
//! ledger for WASM apps running on a cluster (the raft flavor).
//!
//! ## Model
//!
//! An app function invoked THROUGH the cluster transaction path (the
//! `raft_wasm_txn` envelope) executes against a **fork** of the ledger
//! at its committed root. `get` reads through the overlay; `put` /
//! `delete` buffer into it. When the function returns successfully the
//! runtime seals the fork into `(root_before, write-set, root_after)`
//! and proposes it through consensus; every replica applies the same
//! write-set fail-closed and the quorum confirms the resulting root.
//! If the function traps or returns an error, the fork is dropped and
//! the ledger is untouched.
//!
//! Outside a transaction scope every function errors: plain calls do
//! not get ambient write access to replicated state.
//!
//! ## Interface (registered dynamically, like the rest of the SDK)
//!
//!   get:    func(key: list<u8>) -> result<option<list<u8>>, string>
//!   put:    func(key: list<u8>, value: list<u8>) -> result<_, string>
//!   delete: func(key: list<u8>) -> result<_, string>
//!   in-transaction: func() -> bool
//!
//! ## Scoping
//!
//! The active fork is installed for the duration of one execution via
//! [`with_txn_ledger`] (an object-safe [`TxnLedger`] adapter over the
//! raft driver's `MerkleFork`). The enclave dispatcher is
//! single-threaded, so a simple scoped slot is sufficient; the guard
//! restores the previous value on unwind so a trapping guest can never
//! leak a dangling ledger pointer.

use std::cell::Cell;
use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use super::AppContext;

/// Object-safe view of the transaction fork the raft layer installs.
pub trait TxnLedger {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn put(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
}

std::thread_local! {
    /// The active transaction ledger, valid only inside
    /// [`with_txn_ledger`]. Raw pointer because the fork borrows the
    /// raft driver mutably; the scope guard bounds its lifetime.
    static ACTIVE: Cell<Option<*mut dyn TxnLedger>> = const { Cell::new(None) };
}

/// Run `f` with `ledger` installed as the active transaction ledger.
/// Restores the previous slot value on exit (including unwind).
pub fn with_txn_ledger<R>(ledger: &mut dyn TxnLedger, f: impl FnOnce() -> R) -> R {
    struct Guard(Option<*mut dyn TxnLedger>);
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|a| a.set(self.0));
        }
    }
    // Erase the borrow's lifetime for storage in the 'static slot.
    // SAFETY: the guard removes the pointer before `ledger`'s borrow
    // ends (this function's scope), and the single-threaded dispatcher
    // means nothing can observe it after that.
    let ptr: *mut (dyn TxnLedger + 'static) =
        unsafe { core::mem::transmute(ledger as *mut dyn TxnLedger) };
    let _guard = ACTIVE.with(|a| Guard(a.replace(Some(ptr))));
    f()
}

// =========================================================================
//  Deterministic execution scope (replay mode)
// =========================================================================

/// Determinism context for a REPLAY-mode transaction: one shared DRBG
/// (every guest-visible randomness source draws from it, every draw
/// advances it — a replica replaying the same seed reproduces the
/// exact stream) and a frozen wall-clock.
pub struct TxnDeterminism {
    pub drbg: enclave_os_common::drbg::HmacDrbg,
    /// Frozen wall-clock, milliseconds since the epoch (committed in
    /// the entry; both clocks serve it for the whole execution).
    pub timestamp_ms: u64,
}

std::thread_local! {
    static DET: core::cell::RefCell<Option<TxnDeterminism>> =
        const { core::cell::RefCell::new(None) };
}

/// Run `f` with the deterministic scope installed (replay-mode
/// execution on the leader AND on every verifying replica). Restores
/// the previous state on exit, including unwind.
pub fn with_determinism<R>(det: TxnDeterminism, f: impl FnOnce() -> R) -> R {
    struct Guard(Option<TxnDeterminism>);
    impl Drop for Guard {
        fn drop(&mut self) {
            DET.with(|d| *d.borrow_mut() = self.0.take());
        }
    }
    let _guard = Guard(DET.with(|d| d.borrow_mut().replace(det)));
    f()
}

/// Whether the current invocation runs under a deterministic
/// (replay-mode) scope.
pub fn in_replay() -> bool {
    DET.with(|d| d.borrow().is_some())
}

/// Fill `buf` from the transaction DRBG when the deterministic scope
/// is active. Returns false (buf untouched) outside a scope — the
/// caller then uses hardware randomness.
pub fn det_fill(buf: &mut [u8]) -> bool {
    DET.with(|d| match d.borrow_mut().as_mut() {
        Some(det) => {
            det.drbg.fill(buf);
            true
        }
        None => false,
    })
}

/// The frozen wall-clock of the active deterministic scope.
pub fn det_timestamp_ms() -> Option<u64> {
    DET.with(|d| d.borrow().as_ref().map(|det| det.timestamp_ms))
}

/// Access the active ledger, or fail with the out-of-scope error.
fn with_active<R>(
    f: impl FnOnce(&mut dyn TxnLedger) -> R,
) -> Result<R, String> {
    ACTIVE.with(|a| match a.get() {
        // SAFETY: the pointer is installed and cleared by the scope
        // guard in `with_txn_ledger`; the dispatcher is
        // single-threaded, so the borrow cannot alias.
        Some(ptr) => Ok(f(unsafe { &mut *ptr })),
        None => Err(String::from(
            "no active cluster transaction (call this app through raft_wasm_txn)",
        )),
    })
}

// =========================================================================
//  privasys:enclave-os/ledger@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/ledger@0.1.0")?;

    inst.func_wrap(
        "get",
        |_store: StoreContextMut<'_, AppContext>,
         (key,): (Vec<u8>,)|
         -> wasmtime::Result<(Result<Option<Vec<u8>>, String>,)> {
            Ok((with_active(|l| l.get(&key)).and_then(|r| r),))
        },
    )?;

    inst.func_wrap(
        "put",
        |_store: StoreContextMut<'_, AppContext>,
         (key, value): (Vec<u8>, Vec<u8>)|
         -> wasmtime::Result<(Result<(), String>,)> {
            Ok((with_active(|l| l.put(&key, &value)),))
        },
    )?;

    inst.func_wrap(
        "delete",
        |_store: StoreContextMut<'_, AppContext>,
         (key,): (Vec<u8>,)|
         -> wasmtime::Result<(Result<(), String>,)> {
            Ok((with_active(|l| l.delete(&key)),))
        },
    )?;

    inst.func_wrap(
        "in-transaction",
        |_store: StoreContextMut<'_, AppContext>, (): ()| -> wasmtime::Result<(bool,)> {
            Ok((ACTIVE.with(|a| a.get().is_some()),))
        },
    )?;

    Ok(())
}
