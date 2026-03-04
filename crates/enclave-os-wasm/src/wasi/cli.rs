// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `wasi:cli/*`, `wasi:random/*`, `wasi:clocks/*` — simple WASI interfaces.
//!
//! These interfaces don't use complex resources (except stdin/stdout/stderr
//! which return stream resources defined in [`super::io`]).
//!
//! ## Implementations
//!
//! - **random**: RDRAND hardware RNG (no OCALL)
//! - **clocks**: OCALL `get_current_time()` returning UNIX seconds
//! - **environment**: controlled env vars / args from [`AppContext`]
//! - **stdin/stdout/stderr**: return input/output-stream resources
//! - **exit**: trap (abort)

use std::string::String;
use std::vec::Vec;

use wasmtime::component::{Linker, Resource};
use wasmtime::StoreContextMut;

use super::{
    AppContext, InputStreamKind, InputStreamRes, OutputStreamKind,
    OutputStreamRes, PollableRes,
};

// =========================================================================
//  wasi:random/random@0.2.0
// =========================================================================

fn add_random(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:random/random@0.2.0")?;

    // get-random-bytes: func(len: u64) -> list<u8>
    inst.func_wrap(
        "get-random-bytes",
        |_store: StoreContextMut<'_, AppContext>, (len,): (u64,)| {
            let capped = (len as usize).min(65536);
            let mut buf = vec![0u8; capped];
            getrandom::getrandom(&mut buf)
                .map_err(|e| wasmtime::Error::msg(format!("getrandom failed: {}", e)))?;
            Ok((buf,))
        },
    )?;

    // get-random-u64: func() -> u64
    inst.func_wrap(
        "get-random-u64",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf)
                .map_err(|e| wasmtime::Error::msg(format!("getrandom failed: {}", e)))?;
            Ok((u64::from_le_bytes(buf),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:random/insecure@0.2.0  (optional, stub)
// =========================================================================

fn add_random_insecure(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:random/insecure@0.2.0")?;

    inst.func_wrap(
        "get-insecure-random-bytes",
        |_store: StoreContextMut<'_, AppContext>, (len,): (u64,)| {
            let capped = (len as usize).min(65536);
            let mut buf = vec![0u8; capped];
            getrandom::getrandom(&mut buf)
                .map_err(|e| wasmtime::Error::msg(format!("getrandom: {}", e)))?;
            Ok((buf,))
        },
    )?;

    inst.func_wrap(
        "get-insecure-random-u64",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf)
                .map_err(|e| wasmtime::Error::msg(format!("getrandom: {}", e)))?;
            Ok((u64::from_le_bytes(buf),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:random/insecure-seed@0.2.0  (optional, stub)
// =========================================================================

fn add_random_insecure_seed(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:random/insecure-seed@0.2.0")?;

    inst.func_wrap(
        "insecure-seed",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            let mut buf = [0u8; 16];
            getrandom::getrandom(&mut buf).ok();
            let lo = u64::from_le_bytes(buf[..8].try_into().unwrap());
            let hi = u64::from_le_bytes(buf[8..].try_into().unwrap());
            Ok(((lo, hi),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:clocks/wall-clock@0.2.0
// =========================================================================

fn add_wall_clock(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:clocks/wall-clock@0.2.0")?;

    // now: func() -> datetime
    // datetime = record { seconds: u64, nanoseconds: u32 }
    //
    // We use func_new since the return is a record (not a simple tuple).
    inst.func_new(
        "now",
        |_store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let secs = get_time_secs();
            // Return a record { seconds, nanoseconds } — flattened as two vals.
            results[0] = Val::Record(
                vec![
                    ("seconds".into(), Val::U64(secs)),
                    ("nanoseconds".into(), Val::U32(0)),
                ]
                .into(),
            );
            Ok(())
        },
    )?;

    // resolution: func() -> datetime
    inst.func_new(
        "resolution",
        |_store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            results[0] = Val::Record(
                vec![
                    ("seconds".into(), Val::U64(1)),
                    ("nanoseconds".into(), Val::U32(0)),
                ]
                .into(),
            );
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:clocks/monotonic-clock@0.2.0
// =========================================================================

fn add_monotonic_clock(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:clocks/monotonic-clock@0.2.0")?;

    // now: func() -> instant (u64 nanoseconds)
    inst.func_wrap(
        "now",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            let secs = get_time_secs();
            let nanos = secs.saturating_mul(1_000_000_000);
            Ok((nanos,))
        },
    )?;

    // resolution: func() -> instant
    inst.func_wrap(
        "resolution",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            // 1 second resolution (our OCALL returns whole seconds).
            Ok((1_000_000_000u64,))
        },
    )?;

    // subscribe-instant: func(when: instant) -> pollable
    inst.func_wrap(
        "subscribe-instant",
        |mut store: StoreContextMut<'_, AppContext>, (_when,): (u64,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<PollableRes>::new_own(rep),))
        },
    )?;

    // subscribe-duration: func(when: duration) -> pollable
    inst.func_wrap(
        "subscribe-duration",
        |mut store: StoreContextMut<'_, AppContext>, (_duration,): (u64,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<PollableRes>::new_own(rep),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:cli/environment@0.2.0
// =========================================================================

fn add_cli_env(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:cli/environment@0.2.0")?;

    // get-environment: func() -> list<tuple<string, string>>
    inst.func_wrap(
        "get-environment",
        |store: StoreContextMut<'_, AppContext>, _params: ()| {
            let pairs: Vec<(String, String)> = store.data().env_vars.clone();
            Ok((pairs,))
        },
    )?;

    // get-arguments: func() -> list<string>
    inst.func_wrap(
        "get-arguments",
        |store: StoreContextMut<'_, AppContext>, _params: ()| {
            let args: Vec<String> = store.data().args.clone();
            Ok((args,))
        },
    )?;

    // initial-cwd: func() -> option<string>
    inst.func_wrap(
        "initial-cwd",
        |_store: StoreContextMut<'_, AppContext>, _params: ()| {
            Ok((Option::<String>::None,))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:cli/stdin@0.2.0
// =========================================================================

fn add_cli_stdin(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:cli/stdin@0.2.0")?;

    // get-stdin: func() -> input-stream
    inst.func_wrap(
        "get-stdin",
        |mut store: StoreContextMut<'_, AppContext>, _params: ()| {
            let rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .input_streams
                .insert(rep, InputStreamKind::Stdin);
            Ok((Resource::<InputStreamRes>::new_own(rep),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:cli/stdout@0.2.0
// =========================================================================

fn add_cli_stdout(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:cli/stdout@0.2.0")?;

    // get-stdout: func() -> output-stream
    inst.func_wrap(
        "get-stdout",
        |mut store: StoreContextMut<'_, AppContext>, _params: ()| {
            let rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(rep, OutputStreamKind::Stdout);
            Ok((Resource::<OutputStreamRes>::new_own(rep),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:cli/stderr@0.2.0
// =========================================================================

fn add_cli_stderr(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:cli/stderr@0.2.0")?;

    // get-stderr: func() -> output-stream
    inst.func_wrap(
        "get-stderr",
        |mut store: StoreContextMut<'_, AppContext>, _params: ()| {
            let rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(rep, OutputStreamKind::Stderr);
            Ok((Resource::<OutputStreamRes>::new_own(rep),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:cli/exit@0.2.0
// =========================================================================

fn add_cli_exit(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:cli/exit@0.2.0")?;

    // exit: func(status: result)
    //
    // In the Component Model, `result` without type args is
    // `result<_, _>` which is essentially a bool (ok or error).
    inst.func_new(
        "exit",
        |_store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[wasmtime::component::Val],
         _results: &mut [wasmtime::component::Val]| {
            // Trap the WASM execution — the enclave manages its own lifecycle.
            Err(wasmtime::Error::msg("guest called wasi:cli/exit"))
        },
    )?;

    Ok(())
}

// =========================================================================
//  Top-level linker registration
// =========================================================================

/// Register `wasi:random/*`, `wasi:clocks/*`, and `wasi:cli/*` interfaces.
pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    add_random(linker)?;
    add_random_insecure(linker)?;
    add_random_insecure_seed(linker)?;
    add_wall_clock(linker)?;
    add_monotonic_clock(linker)?;
    add_cli_env(linker)?;
    add_cli_stdin(linker)?;
    add_cli_stdout(linker)?;
    add_cli_stderr(linker)?;
    add_cli_exit(linker)?;
    Ok(())
}

// =========================================================================
//  Helpers
// =========================================================================

/// Fetch UNIX timestamp (seconds) via the host OCALL.
fn get_time_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}
