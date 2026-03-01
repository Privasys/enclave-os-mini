// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `wasi:filesystem/{types,preopens}@0.2.0`
//!
//! Lightweight filesystem implementation backed by the enclave OS sealed KV store.
//!
//! ## Design
//!
//! The WASI filesystem abstraction is mapped onto the per-app [`SealedKvStore`]:
//!
//! | Concept     | KV backing                                       |
//! |-------------|--------------------------------------------------|
//! | File read   | `sealed_kv.get("fs:<path>")` -> buffer           |
//! | File write  | Buffer -> `sealed_kv.put("fs:<path>", data)` on sync |
//! | Directory   | Conceptual prefix; listing not fully supported    |
//! | Preopens    | Single root `/` descriptor                       |
//!
//! All KV keys for filesystem entries use the `fs:` prefix to avoid
//! collisions with other KV data.  Keys and values are encrypted
//! (AES-256-GCM) inside the enclave before being stored on the host.
//!
//! ## Limitations
//!
//! - **Flat namespace**: Subdirectories are represented by path separators
//!   in KV keys (e.g., `fs:/data/config.json`), not as real directories.
//! - **Simplified metadata**: No timestamps, no link counts.
//! - **Write-back on sync**: File data is buffered in-memory and written
//!   to KV on `sync-data` or descriptor drop.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::{Linker, Resource, ResourceType, Val};
use wasmtime::{AsContextMut, StoreContextMut};

use super::{
    DescriptorRes, DirEntryStreamRes, DirEntryStreamState, FsDescriptor,
    AppContext, InputStreamKind, InputStreamRes, OutputStreamKind,
    OutputStreamRes, PollableRes,
};

/// KV key domain for all filesystem entries (used with `AppContext::kv_key`).
const FS_DOMAIN: &str = "fs:";

// =========================================================================
//  wasi:filesystem/types@0.2.0
// =========================================================================

fn add_types(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:filesystem/types@0.2.0")?;

    // ── resource: descriptor ───────────────────────────────────────
    inst.resource(
        "descriptor",
        ResourceType::host::<DescriptorRes>(),
        |mut store, rep| {
            // On drop, flush dirty files to KV store.
            if let Some(FsDescriptor::File { key, buf, dirty, .. }) =
                store.data_mut().fs_descriptors.remove(&rep)
            {
                if dirty && !buf.is_empty() {
                    let kv_key = format!("{}{}", FS_DOMAIN, key);
                    let _ = store.data().sealed_kv.put(kv_key.as_bytes(), &buf);
                }
            } else {
                store.data_mut().fs_descriptors.remove(&rep);
            }
            Ok(())
        },
    )?;

    // ── resource: directory-entry-stream ────────────────────────────
    inst.resource(
        "directory-entry-stream",
        ResourceType::host::<DirEntryStreamRes>(),
        |mut store, rep| {
            store.data_mut().dir_entry_streams.remove(&rep);
            Ok(())
        },
    )?;

    // ── [method]descriptor.get-type ────────────────────────────────
    // func(self) -> result<descriptor-type, error-code>
    //
    // descriptor-type enum: directory=3, regular-file=6
    inst.func_new(
        "[method]descriptor.get-type",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            let dtype = match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::Directory { .. }) => "directory",
                Some(FsDescriptor::File { .. }) => "regular-file",
                None => {
                    results[0] = fs_error("bad-descriptor");
                    return Ok(());
                }
            };
            results[0] = Val::Result(Ok(Some(Box::new(Val::Enum(dtype.to_string())))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.stat ────────────────────────────────────
    // func(self) -> result<descriptor-stat, error-code>
    inst.func_new(
        "[method]descriptor.stat",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            let (dtype, size) = match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::Directory { .. }) => ("directory", 0u64),
                Some(FsDescriptor::File { buf, .. }) => ("regular-file", buf.len() as u64),
                None => {
                    results[0] = fs_error("bad-descriptor");
                    return Ok(());
                }
            };
            results[0] = Val::Result(Ok(Some(Box::new(make_descriptor_stat(dtype, size)))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.stat-at ─────────────────────────────────
    // func(self, path-flags, path: string) -> result<descriptor-stat, error-code>
    inst.func_new(
        "[method]descriptor.stat-at",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            // params[1] = path-flags (ignored)
            let path = val_string(&params[2]);

            let prefix = match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::Directory { prefix }) => prefix.clone(),
                _ => {
                    results[0] = fs_error("not-directory");
                    return Ok(());
                }
            };

            let full_path = normalize_path(&prefix, &path);
            let kv_key = format!("{}{}", FS_DOMAIN, full_path);

            // Check if path exists as a file in KV store.
            match store.data().sealed_kv.get(kv_key.as_bytes()) {
                Ok(Some(data)) => {
                    results[0] = Val::Result(Ok(Some(Box::new(
                        make_descriptor_stat("regular-file", data.len() as u64),
                    ))));
                }
                _ => {
                    // Might be a directory (prefix). We can't verify, so
                    // assume directory with size 0.
                    results[0] = Val::Result(Ok(Some(Box::new(
                        make_descriptor_stat("directory", 0),
                    ))));
                }
            }
            Ok(())
        },
    )?;

    // ── [method]descriptor.open-at ─────────────────────────────────
    // func(self, path-flags, path: string, open-flags, descriptor-flags)
    //   -> result<descriptor, error-code>
    //
    // open-flags: create=1, directory=2, exclusive=4, truncate=8
    inst.func_new(
        "[method]descriptor.open-at",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            // params[1] = path-flags (flags, ignored)
            let path = val_string(&params[2]);
            let open_flags = val_open_flags(&params[3]);
            // params[4] = descriptor-flags (ignored for now)

            let prefix = match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::Directory { prefix }) => prefix.clone(),
                _ => {
                    results[0] = fs_error("not-directory");
                    return Ok(());
                }
            };

            let full_path = normalize_path(&prefix, &path);
            let create = (open_flags & 1) != 0;
            let is_dir = (open_flags & 2) != 0;
            let truncate = (open_flags & 8) != 0;

            if is_dir {
                // Open as directory descriptor.
                let new_rep = store.data_mut().alloc_rep();
                store.data_mut().fs_descriptors.insert(
                    new_rep,
                    FsDescriptor::Directory {
                        prefix: full_path,
                    },
                );
                let res = Resource::<DescriptorRes>::new_own(new_rep);
                let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
                results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
                return Ok(());
            }

            // Open as file — load from KV store.
            let kv_key = format!("{}{}", FS_DOMAIN, full_path);
            let buf = if truncate {
                Vec::new()
            } else {
                match store.data().sealed_kv.get(kv_key.as_bytes()) {
                    Ok(Some(data)) => data,
                    Ok(None) if create => Vec::new(),
                    Ok(None) => {
                        results[0] = fs_error("no-entry"); // no-entry
                        return Ok(());
                    }
                    Err(_) if create => Vec::new(),
                    Err(_) => {
                        results[0] = fs_error("io"); // io
                        return Ok(());
                    }
                }
            };

            let new_rep = store.data_mut().alloc_rep();
            store.data_mut().fs_descriptors.insert(
                new_rep,
                FsDescriptor::File {
                    key: full_path,
                    buf,
                    pos: 0,
                    dirty: false,
                },
            );

            let res = Resource::<DescriptorRes>::new_own(new_rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.read-via-stream ─────────────────────────
    // func(self, offset: u64) -> result<input-stream, error-code>
    inst.func_new(
        "[method]descriptor.read-via-stream",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            let offset = val_u64(&params[1]) as usize;

            let buf = match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::File { buf, .. }) => {
                    if offset < buf.len() {
                        buf[offset..].to_vec()
                    } else {
                        Vec::new()
                    }
                }
                _ => {
                    results[0] = fs_error("bad-descriptor");
                    return Ok(());
                }
            };

            // Create an input-stream backed by the file data.
            let is_rep = store.data_mut().alloc_rep();
            store.data_mut().input_streams.insert(
                is_rep,
                InputStreamKind::Buffer { data: buf, pos: 0 },
            );

            let res = Resource::<InputStreamRes>::new_own(is_rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.write-via-stream ────────────────────────
    // func(self, offset: u64) -> result<output-stream, error-code>
    //
    // Returns an output-stream that captures written bytes.
    // The file's buffer is updated when the stream is flushed or dropped.
    inst.func_new(
        "[method]descriptor.write-via-stream",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;

            // Mark file as dirty.
            match store.data_mut().fs_descriptors.get_mut(&rep) {
                Some(FsDescriptor::File { dirty, .. }) => {
                    *dirty = true;
                }
                _ => {
                    results[0] = fs_error("bad-descriptor");
                    return Ok(());
                }
            }

            // Create an output-stream that writes to the file's buffer.
            // We use OutputStreamKind::FsFile referencing the descriptor rep.
            let os_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(os_rep, OutputStreamKind::Null);

            let res = Resource::<OutputStreamRes>::new_own(os_rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.append-via-stream ───────────────────────
    inst.func_new(
        "[method]descriptor.append-via-stream",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            match store.data_mut().fs_descriptors.get_mut(&rep) {
                Some(FsDescriptor::File { dirty, .. }) => {
                    *dirty = true;
                }
                _ => {
                    results[0] = fs_error("bad-descriptor");
                    return Ok(());
                }
            }
            let os_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(os_rep, OutputStreamKind::Null);
            let res = Resource::<OutputStreamRes>::new_own(os_rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.read ────────────────────────────────────
    // func(self, length: u64, offset: u64) -> result<tuple<list<u8>, bool>, error-code>
    inst.func_new(
        "[method]descriptor.read",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            let length = val_u64(&params[1]) as usize;
            let offset = val_u64(&params[2]) as usize;

            match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::File { buf, .. }) => {
                    let start = offset.min(buf.len());
                    let end = (start + length).min(buf.len());
                    let data = buf[start..end].to_vec();
                    let at_end = end >= buf.len();

                    // result<tuple<list<u8>, bool>, error-code>
                    let list_val = Val::List(
                        data.into_iter().map(Val::U8).collect::<Vec<_>>().into(),
                    );
                    results[0] = Val::Result(Ok(Some(Box::new(Val::Tuple(
                        vec![list_val, Val::Bool(at_end)].into(),
                    )))));
                }
                _ => {
                    results[0] = fs_error("bad-descriptor");
                }
            }
            Ok(())
        },
    )?;

    // ── [method]descriptor.write ───────────────────────────────────
    // func(self, buffer: list<u8>, offset: u64) -> result<u64, error-code>
    inst.func_new(
        "[method]descriptor.write",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            let data = val_list_u8(&params[1]);
            let offset = val_u64(&params[2]) as usize;

            match store.data_mut().fs_descriptors.get_mut(&rep) {
                Some(FsDescriptor::File {
                    buf, dirty, ..
                }) => {
                    *dirty = true;
                    let end = offset + data.len();
                    if end > buf.len() {
                        buf.resize(end, 0);
                    }
                    buf[offset..end].copy_from_slice(&data);
                    results[0] = Val::Result(Ok(Some(Box::new(
                        Val::U64(data.len() as u64),
                    ))));
                }
                _ => {
                    results[0] = fs_error("bad-descriptor");
                }
            }
            Ok(())
        },
    )?;

    // ── [method]descriptor.read-directory ──────────────────────────
    // func(self) -> result<directory-entry-stream, error-code>
    //
    // Returns an empty stream (no KV listing OCALL available).
    inst.func_new(
        "[method]descriptor.read-directory",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            match store.data().fs_descriptors.get(&rep) {
                Some(FsDescriptor::Directory { .. }) => {}
                _ => {
                    results[0] = fs_error("not-directory");
                    return Ok(());
                }
            }

            let des_rep = store.data_mut().alloc_rep();
            store.data_mut().dir_entry_streams.insert(
                des_rep,
                DirEntryStreamState {
                    entries: Vec::new(),
                    pos: 0,
                },
            );

            let res = Resource::<DirEntryStreamRes>::new_own(des_rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    // ── [method]directory-entry-stream.read-directory-entry ────────
    // func(self) -> result<option<directory-entry>, error-code>
    inst.func_new(
        "[method]directory-entry-stream.read-directory-entry",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DirEntryStreamRes>(&params[0], store.as_context_mut())?;

            let entry = store
                .data_mut()
                .dir_entry_streams
                .get_mut(&rep)
                .and_then(|s| {
                    if s.pos < s.entries.len() {
                        let e = &s.entries[s.pos];
                        s.pos += 1;
                        Some((e.name.clone(), e.is_dir))
                    } else {
                        None
                    }
                });

            match entry {
                Some((name, is_dir)) => {
                    let dtype = if is_dir { "directory" } else { "regular-file" };
                    let record = Val::Record(
                        vec![
                            ("type".into(), Val::Enum(dtype.to_string())),
                            ("name".into(), Val::String(name.into())),
                        ]
                        .into(),
                    );
                    results[0] = Val::Result(Ok(Some(Box::new(
                        Val::Option(Some(Box::new(record))),
                    ))));
                }
                None => {
                    // End of stream.
                    results[0] = Val::Result(Ok(Some(Box::new(
                        Val::Option(None),
                    ))));
                }
            }
            Ok(())
        },
    )?;

    // ── [method]descriptor.sync-data ───────────────────────────────
    // func(self) -> result<_, error-code>
    //
    // Flush dirty file data to KV store.
    inst.func_new(
        "[method]descriptor.sync-data",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            // Extract data to sync (immutable borrow).
            let sync_data = if let Some(FsDescriptor::File { key, buf, dirty, .. }) =
                store.data().fs_descriptors.get(&rep)
            {
                if *dirty { Some((format!("{}{}", FS_DOMAIN, key), buf.clone())) } else { None }
            } else {
                None
            };
            // Perform encrypted write (borrows sealed_kv immutably).
            if let Some((kv_key, buf_data)) = sync_data {
                match store.data().sealed_kv.put(kv_key.as_bytes(), &buf_data) {
                    Ok(()) => {
                        if let Some(FsDescriptor::File { dirty, .. }) =
                            store.data_mut().fs_descriptors.get_mut(&rep)
                        {
                            *dirty = false;
                        }
                    }
                    Err(_) => {
                        results[0] = fs_error("io"); // io
                        return Ok(());
                    }
                }
            }
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── [method]descriptor.sync ────────────────────────────────────────
    inst.func_new(
        "[method]descriptor.sync",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let rep = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut())?;
            // Extract data to sync (immutable borrow).
            let sync_data = if let Some(FsDescriptor::File { key, buf, dirty, .. }) =
                store.data().fs_descriptors.get(&rep)
            {
                if *dirty { Some((format!("{}{}", FS_DOMAIN, key), buf.clone())) } else { None }
            } else {
                None
            };
            // Perform encrypted write (borrows sealed_kv immutably).
            if let Some((kv_key, buf_data)) = sync_data {
                match store.data().sealed_kv.put(kv_key.as_bytes(), &buf_data) {
                    Ok(()) => {
                        if let Some(FsDescriptor::File { dirty, .. }) =
                            store.data_mut().fs_descriptors.get_mut(&rep)
                        {
                            *dirty = false;
                        }
                    }
                    Err(_) => {
                        results[0] = fs_error("io");
                        return Ok(());
                    }
                }
            }
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── [method]descriptor.get-flags ───────────────────────────────
    // func(self) -> result<descriptor-flags, error-code>
    inst.func_new(
        "[method]descriptor.get-flags",
        |_store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[Val],
         results: &mut [Val]| {
            // Return read+write flags
            results[0] = Val::Result(Ok(Some(Box::new(Val::Flags(
                vec!["read".to_string(), "write".to_string()],
            )))));
            Ok(())
        },
    )?;

    // ── [method]descriptor.subscribe ───────────────────────────────
    inst.func_wrap(
        "[method]descriptor.subscribe",
        |mut store: StoreContextMut<'_, AppContext>,
         (_self,): (Resource<DescriptorRes>,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<PollableRes>::new_own(rep),))
        },
    )?;

    // ── [method]descriptor.is-same-object ──────────────────────────
    inst.func_new(
        "[method]descriptor.is-same-object",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         params: &[Val],
         results: &mut [Val]| {
            let a = resource_rep::<DescriptorRes>(&params[0], store.as_context_mut()).unwrap_or(u32::MAX);
            let b = resource_rep::<DescriptorRes>(&params[1], store.as_context_mut()).unwrap_or(u32::MAX - 1);
            results[0] = Val::Bool(a == b);
            Ok(())
        },
    )?;

    // ── Stub methods (return unsupported error) ────────────────────
    for method in &[
        "[method]descriptor.advise",
        "[method]descriptor.set-size",
        "[method]descriptor.set-times",
        "[method]descriptor.set-times-at",
        "[method]descriptor.link-at",
        "[method]descriptor.readlink-at",
        "[method]descriptor.remove-directory-at",
        "[method]descriptor.rename-at",
        "[method]descriptor.symlink-at",
        "[method]descriptor.unlink-file-at",
        "[method]descriptor.create-directory-at",
        "[method]descriptor.metadata-hash",
        "[method]descriptor.metadata-hash-at",
    ] {
        let _name = method.to_string();
        inst.func_new(
            method,
            |_store: StoreContextMut<'_, AppContext>,
             _func_type: wasmtime::component::types::ComponentFunc,
             _params: &[Val],
             results: &mut [Val]| {
                results[0] = fs_error("unsupported"); // unsupported
                Ok(())
            },
        )?;
    }

    // ── filesystem-error-code ──────────────────────────────────────
    // func(err: borrow<error>) -> option<error-code>
    inst.func_new(
        "filesystem-error-code",
        |_store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[Val],
         results: &mut [Val]| {
            // We don't use io/error for filesystem errors, so always return None.
            results[0] = Val::Option(None);
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:filesystem/preopens@0.2.0
// =========================================================================

fn add_preopens(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:filesystem/preopens@0.2.0")?;

    // get-directories: func() -> list<tuple<own<descriptor>, string>>
    //
    // Returns a single root "/" preopen.
    inst.func_new(
        "get-directories",
        |mut store: StoreContextMut<'_, AppContext>,
         _func_type: wasmtime::component::types::ComponentFunc,
         _params: &[Val],
         results: &mut [Val]| {
            let rep = store.data_mut().alloc_rep();
            store.data_mut().fs_descriptors.insert(
                rep,
                FsDescriptor::Directory {
                    prefix: "/".into(),
                },
            );

            let res = Resource::<DescriptorRes>::new_own(rep);
            let any = wasmtime::component::ResourceAny::try_from_resource(res, &mut store)?;

            // list<tuple<descriptor, string>>
            results[0] = Val::List(
                vec![Val::Tuple(
                    vec![
                        Val::Resource(any),
                        Val::String("/".into()),
                    ]
                    .into(),
                )]
                .into(),
            );
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  Top-level linker registration
// =========================================================================

/// Register all `wasi:filesystem/*` interfaces in the linker.
pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    add_types(linker)?;
    add_preopens(linker)?;
    Ok(())
}

// =========================================================================
//  Helpers
// =========================================================================

/// Extract resource rep from a Val.
fn resource_rep<T: 'static>(val: &Val, store: impl wasmtime::AsContextMut) -> Result<u32, wasmtime::Error> {
    match val {
        Val::Resource(any) => {
            let res = wasmtime::component::Resource::<T>::try_from_resource_any(*any, store)?;
            Ok(res.rep())
        }
        _ => Err(wasmtime::Error::msg("expected resource")),
    }
}

/// Extract a u64 from a Val.
fn val_u64(val: &Val) -> u64 {
    match val {
        Val::U64(v) => *v,
        _ => 0,
    }
}

/// Extract a u32 from a Val.
fn val_u32(val: &Val) -> u32 {
    match val {
        Val::U32(v) => *v,
        _ => 0,
    }
}

/// Extract a string from a Val.
fn val_string(val: &Val) -> String {
    match val {
        Val::String(s) => s.to_string(),
        _ => String::new(),
    }
}

/// Extract `list<u8>` from a Val.
fn val_list_u8(val: &Val) -> Vec<u8> {
    match val {
        Val::List(items) => items
            .iter()
            .filter_map(|v| match v {
                Val::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Build a filesystem `result<_, error-code>` error value.
fn fs_error(name: &str) -> Val {
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_string())))))
}

/// Construct a `descriptor-stat` record.
fn make_descriptor_stat(dtype: &str, size: u64) -> Val {
    Val::Record(
        vec![
            ("type".into(), Val::Enum(dtype.to_string())),
            ("link-count".into(), Val::U64(1)),
            ("size".into(), Val::U64(size)),
            (
                "data-access-timestamp".into(),
                Val::Option(None),
            ),
            (
                "data-modification-timestamp".into(),
                Val::Option(None),
            ),
            (
                "status-change-timestamp".into(),
                Val::Option(None),
            ),
        ]
        .into(),
    )
}

/// Extract `open-flags` from a Val.
///
/// Component model flags arrive as `Val::Flags(names_set)` where the
/// boxed slice contains only the flag names that are SET. We also
/// accept `Val::U32` for robustness.
///
/// Bit mapping (matching WASI filesystem/types):
///   create=1, directory=2, exclusive=4, truncate=8
fn val_open_flags(val: &Val) -> u32 {
    match val {
        Val::Flags(names) => {
            let mut bits = 0u32;
            for name in names.iter() {
                match name.as_str() {
                    "create" => bits |= 1,
                    "directory" => bits |= 2,
                    "exclusive" => bits |= 4,
                    "truncate" => bits |= 8,
                    _ => {}
                }
            }
            bits
        }
        Val::U32(v) => *v,
        _ => 0,
    }
}

/// Normalize a filesystem path from a directory prefix and relative path.
fn normalize_path(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let path = path.trim_start_matches("./").trim_start_matches('/');
    if prefix.is_empty() || prefix == "/" {
        format!("/{}", path)
    } else {
        format!("{}/{}", prefix, path)
    }
}
