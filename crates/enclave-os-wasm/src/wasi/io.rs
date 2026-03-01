// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `wasi:io/{error,poll,streams}@0.2.0` — resource-based I/O primitives.
//!
//! This is the foundation of the WASI I/O model.  All other WASI
//! interfaces that perform I/O (cli, sockets, filesystem) build on top
//! of these resources.
//!
//! ## Resources
//!
//! - **error** (`wasi:io/error`) — opaque error with a debug string.
//! - **pollable** (`wasi:io/poll`) — synchronous (always-ready) poll token.
//! - **input-stream** / **output-stream** (`wasi:io/streams`) — byte
//!   streams backed by AppContext I/O buffers, sockets, or the KV store.

use wasmtime::component::{Linker, Resource, ResourceType};
use wasmtime::{AsContextMut, StoreContextMut};

use super::{
    AppContext, InputStreamRes, IoErrorRes, OutputStreamKind,
    OutputStreamRes, PollableRes,
};

// =========================================================================
//  wasi:io/error@0.2.0
// =========================================================================

pub fn add_io_error(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:io/error@0.2.0")?;

    // ── resource: error ────────────────────────────────────────────
    inst.resource("error", ResourceType::host::<IoErrorRes>(), |mut store, rep| {
        store.data_mut().errors.remove(&rep);
        Ok(())
    })?;

    // [method]error.to-debug-string: func() -> string
    inst.func_wrap(
        "[method]error.to-debug-string",
        |store: StoreContextMut<'_, AppContext>, (self_,): (Resource<IoErrorRes>,)| {
            let msg = store
                .data()
                .errors
                .get(&self_.rep())
                .cloned()
                .unwrap_or_else(|| String::from("unknown error"));
            Ok((msg,))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:io/poll@0.2.0
// =========================================================================

pub fn add_io_poll(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:io/poll@0.2.0")?;

    // ── resource: pollable ─────────────────────────────────────────
    inst.resource(
        "pollable",
        ResourceType::host::<PollableRes>(),
        |_store, _rep| Ok(()),
    )?;

    // [method]pollable.ready: func() -> bool
    inst.func_wrap(
        "[method]pollable.ready",
        |_store: StoreContextMut<'_, AppContext>, (_self,): (Resource<PollableRes>,)| {
            // In our synchronous model, everything is always ready.
            Ok((true,))
        },
    )?;

    // [method]pollable.block: func()
    inst.func_wrap(
        "[method]pollable.block",
        |_store: StoreContextMut<'_, AppContext>, (_self,): (Resource<PollableRes>,)| {
            // No-op: we're always ready.
            Ok(())
        },
    )?;

    // poll: func(in: list<borrow<pollable>>) -> list<u32>
    inst.func_wrap(
        "poll",
        |_store: StoreContextMut<'_, AppContext>,
         (pollables,): (Vec<Resource<PollableRes>>,)| {
            // All pollables are ready → return all indices.
            let ready: Vec<u32> = (0..pollables.len() as u32).collect();
            Ok((ready,))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:io/streams@0.2.0
// =========================================================================

pub fn add_io_streams(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:io/streams@0.2.0")?;

    // ── resource: input-stream ─────────────────────────────────────
    inst.resource(
        "input-stream",
        ResourceType::host::<InputStreamRes>(),
        |mut store, rep| {
            store.data_mut().input_streams.remove(&rep);
            Ok(())
        },
    )?;

    // ── resource: output-stream ────────────────────────────────────
    inst.resource(
        "output-stream",
        ResourceType::host::<OutputStreamRes>(),
        |mut store, rep| {
            // If this was a socket stream, don't close the fd here — the
            // socket resource owns it.
            store.data_mut().output_streams.remove(&rep);
            Ok(())
        },
    )?;

    // ----------------------------------------------------------------
    //  input-stream methods
    // ----------------------------------------------------------------

    // [method]input-stream.read: func(len: u64) -> result<list<u8>, stream-error>
    //
    // stream-error is a variant { last-operation-failed(error), closed }.
    // We use func_new for the dynamic Val API to handle the variant return.
    inst.func_new(
        "[method]input-stream.read",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<InputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;

            let data = store.data_mut().read_stream(rep, len);
            match data {
                Ok(bytes) => {
                    let list: Vec<Val> = bytes.into_iter().map(Val::U8).collect();
                    results[0] = Val::Result(Ok(Some(Box::new(Val::List(list.into())))));
                }
                Err("closed") => {
                    results[0] = Val::Result(Err(Some(Box::new(
                        Val::Variant("closed".to_string(), None), // stream-error::closed
                    ))));
                }
                Err(_) => {
                    // last-operation-failed — we skip the error resource for simplicity
                    results[0] = Val::Result(Err(Some(Box::new(
                        Val::Variant("closed".to_string(), None), // fallback to closed
                    ))));
                }
            }
            Ok(())
        },
    )?;

    // [method]input-stream.blocking-read: func(len: u64) -> result<list<u8>, stream-error>
    inst.func_new(
        "[method]input-stream.blocking-read",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<InputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;

            match store.data_mut().read_stream(rep, len) {
                Ok(bytes) => {
                    let list: Vec<Val> = bytes.into_iter().map(Val::U8).collect();
                    results[0] = Val::Result(Ok(Some(Box::new(Val::List(list.into())))));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]input-stream.skip: func(len: u64) -> result<u64, stream-error>
    inst.func_new(
        "[method]input-stream.skip",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<InputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;

            match store.data_mut().read_stream(rep, len) {
                Ok(bytes) => {
                    results[0] =
                        Val::Result(Ok(Some(Box::new(Val::U64(bytes.len() as u64)))));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]input-stream.blocking-skip: func(len: u64) -> result<u64, stream-error>
    inst.func_new(
        "[method]input-stream.blocking-skip",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<InputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;

            match store.data_mut().read_stream(rep, len) {
                Ok(bytes) => {
                    results[0] =
                        Val::Result(Ok(Some(Box::new(Val::U64(bytes.len() as u64)))));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]input-stream.subscribe: func() -> pollable
    inst.func_wrap(
        "[method]input-stream.subscribe",
        |mut store: StoreContextMut<'_, AppContext>,
         (_self,): (Resource<InputStreamRes>,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<PollableRes>::new_own(rep),))
        },
    )?;

    // ----------------------------------------------------------------
    //  output-stream methods
    // ----------------------------------------------------------------

    // [method]output-stream.check-write: func() -> result<u64, stream-error>
    inst.func_new(
        "[method]output-stream.check-write",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;

            if store.data().output_streams.contains_key(&rep) {
                // Report 64 KiB writable (generous buffer).
                results[0] = Val::Result(Ok(Some(Box::new(Val::U64(65536)))));
            } else {
                results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
            }
            Ok(())
        },
    )?;

    // [method]output-stream.write: func(contents: list<u8>) -> result<_, stream-error>
    inst.func_new(
        "[method]output-stream.write",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let data = val_list_u8(&params[1])?;

            match store.data_mut().write_stream(rep, &data) {
                Ok(()) => {
                    results[0] = Val::Result(Ok(None)); // result<_, _>::ok(())
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]output-stream.blocking-write-and-flush: func(contents: list<u8>) -> result<_, stream-error>
    inst.func_new(
        "[method]output-stream.blocking-write-and-flush",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let data = val_list_u8(&params[1])?;

            match store.data_mut().write_stream(rep, &data) {
                Ok(()) => {
                    results[0] = Val::Result(Ok(None));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]output-stream.flush: func() -> result<_, stream-error>
    inst.func_new(
        "[method]output-stream.flush",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            let _rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            // Flush is a no-op for memory buffers and OCALLs (already delivered).
            results[0] = wasmtime::component::Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // [method]output-stream.blocking-flush: func() -> result<_, stream-error>
    inst.func_new(
        "[method]output-stream.blocking-flush",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            let _rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            results[0] = wasmtime::component::Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // [method]output-stream.subscribe: func() -> pollable
    inst.func_wrap(
        "[method]output-stream.subscribe",
        |mut store: StoreContextMut<'_, AppContext>,
         (_self,): (Resource<OutputStreamRes>,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<PollableRes>::new_own(rep),))
        },
    )?;

    // [method]output-stream.write-zeroes: func(len: u64) -> result<_, stream-error>
    inst.func_new(
        "[method]output-stream.write-zeroes",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;
            let zeroes = vec![0u8; len.min(65536)];

            match store.data_mut().write_stream(rep, &zeroes) {
                Ok(()) => results[0] = Val::Result(Ok(None)),
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]output-stream.blocking-write-zeroes-and-flush
    inst.func_new(
        "[method]output-stream.blocking-write-zeroes-and-flush",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let len = val_u64(&params[1])? as usize;
            let zeroes = vec![0u8; len.min(65536)];

            match store.data_mut().write_stream(rep, &zeroes) {
                Ok(()) => results[0] = Val::Result(Ok(None)),
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]output-stream.splice: func(src: borrow<input-stream>, len: u64) -> result<u64, stream-error>
    inst.func_new(
        "[method]output-stream.splice",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let out_rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let in_rep = resource_rep::<InputStreamRes>(&params[1], store.as_context_mut())?;
            let len = val_u64(&params[2])? as usize;

            // Read from input, write to output
            let data = match store.data_mut().read_stream(in_rep, len) {
                Ok(d) => d,
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                    return Ok(());
                }
            };
            let written = data.len();
            match store.data_mut().write_stream(out_rep, &data) {
                Ok(()) => {
                    results[0] =
                        Val::Result(Ok(Some(Box::new(Val::U64(written as u64)))));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    // [method]output-stream.blocking-splice (same as splice in sync model)
    inst.func_new(
        "[method]output-stream.blocking-splice",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[wasmtime::component::Val],
         results: &mut [wasmtime::component::Val]| {
            use wasmtime::component::Val;
            let out_rep = resource_rep::<OutputStreamRes>(&params[0], store.as_context_mut())?;
            let in_rep = resource_rep::<InputStreamRes>(&params[1], store.as_context_mut())?;
            let len = val_u64(&params[2])? as usize;

            let data = match store.data_mut().read_stream(in_rep, len) {
                Ok(d) => d,
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                    return Ok(());
                }
            };
            let written = data.len();
            match store.data_mut().write_stream(out_rep, &data) {
                Ok(()) => {
                    results[0] =
                        Val::Result(Ok(Some(Box::new(Val::U64(written as u64)))));
                }
                Err(_) => {
                    results[0] = Val::Result(Err(Some(Box::new(Val::Variant("closed".to_string(), None)))));
                }
            }
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  Top-level linker registration
// =========================================================================

/// Register all `wasi:io/*` interfaces in the linker.
pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    add_io_error(linker)?;
    add_io_poll(linker)?;
    add_io_streams(linker)?;
    Ok(())
}

// =========================================================================
//  Val helper functions (for func_new dynamic dispatch)
// =========================================================================

/// Extract the resource representation (u32) from a `Val::Resource`.
fn resource_rep<T: 'static>(val: &wasmtime::component::Val, store: impl wasmtime::AsContextMut) -> Result<u32, wasmtime::Error> {
    match val {
        wasmtime::component::Val::Resource(any) => {
            let res = wasmtime::component::Resource::<T>::try_from_resource_any(*any, store)?;
            Ok(res.rep())
        }
        _ => Err(wasmtime::Error::msg("expected resource value")),
    }
}

/// Extract a u64 from a `Val`.
fn val_u64(val: &wasmtime::component::Val) -> Result<u64, wasmtime::Error> {
    match val {
        wasmtime::component::Val::U64(n) => Ok(*n),
        _ => Err(wasmtime::Error::msg("expected u64 value")),
    }
}

/// Extract a `list<u8>` from a `Val::List`.
fn val_list_u8(val: &wasmtime::component::Val) -> Result<Vec<u8>, wasmtime::Error> {
    match val {
        wasmtime::component::Val::List(items) => {
            let mut buf = Vec::with_capacity(items.len());
            for item in items.iter() {
                match item {
                    wasmtime::component::Val::U8(b) => buf.push(*b),
                    _ => return Err(wasmtime::Error::msg("expected list<u8>")),
                }
            }
            Ok(buf)
        }
        _ => Err(wasmtime::Error::msg("expected list value")),
    }
}
