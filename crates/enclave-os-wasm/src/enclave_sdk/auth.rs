// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/auth@0.1.0` — Caller identity & role management for WASM apps.
//!
//! Exposes the authenticated caller's identity and roles to the guest,
//! plus management functions (list users, get/set/remove roles) that
//! enforce admin-level checks on the host side.
//!
//! ## Caller context
//!
//! The caller's identity (`caller_id`) and roles (`caller_roles`) are
//! populated on the [`AppContext`] by the dispatch path **before** the
//! WASM function is invoked.  The functions here read those fields.
//!
//! ## Role storage
//!
//! Role management functions delegate to [`enclave_os_app_auth`] which
//! persists roles in the app's sealed KV store under the `roles:` prefix.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use super::AppContext;

// =========================================================================
//  privasys:enclave-os/auth@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/auth@0.1.0")?;

    // ── get-caller-id ──────────────────────────────────────────────
    inst.func_wrap(
        "get-caller-id",
        |store: StoreContextMut<'_, AppContext>, (): ()| -> wasmtime::Result<(Result<String, String>,)> {
            let ctx = store.data();
            match &ctx.caller_id {
                Some(id) => Ok((Ok(id.clone()),)),
                None => Ok((Err("not authenticated".into()),)),
            }
        },
    )?;

    // ── get-my-roles ───────────────────────────────────────────────
    inst.func_wrap(
        "get-my-roles",
        |store: StoreContextMut<'_, AppContext>, (): ()| -> wasmtime::Result<(Result<Vec<String>, String>,)> {
            let ctx = store.data();
            if ctx.caller_id.is_none() {
                return Ok((Err("not authenticated".into()),));
            }
            Ok((Ok(ctx.caller_roles.clone()),))
        },
    )?;

    // ── list-users ─────────────────────────────────────────────────
    inst.func_wrap(
        "list-users",
        |store: StoreContextMut<'_, AppContext>, (): ()| -> wasmtime::Result<(Result<Vec<(String, Vec<String>)>, String>,)> {
            let ctx = store.data();

            // Require admin or user-management role.
            if !has_any_role(&ctx.caller_roles, &["admin", "user-management"]) {
                return Ok((Err("requires 'admin' or 'user-management' role".into()),));
            }

            #[cfg(feature = "app-auth")]
            {
                match enclave_os_app_auth::list_users(&ctx.sealed_kv) {
                    Ok(users) => Ok((Ok(users),)),
                    Err(e) => Ok((Err(e),)),
                }
            }

            #[cfg(not(feature = "app-auth"))]
            {
                Ok((Err("role management requires app-auth feature".into()),))
            }
        },
    )?;

    // ── get-user-roles ─────────────────────────────────────────────
    inst.func_wrap(
        "get-user-roles",
        |store: StoreContextMut<'_, AppContext>, (user_id,): (String,)| -> wasmtime::Result<(Result<Vec<String>, String>,)> {
            let ctx = store.data();

            if !has_any_role(&ctx.caller_roles, &["admin", "user-management"]) {
                return Ok((Err("requires 'admin' or 'user-management' role".into()),));
            }

            #[cfg(feature = "app-auth")]
            {
                match enclave_os_app_auth::get_user_roles(&ctx.sealed_kv, &user_id) {
                    Ok(roles) => Ok((Ok(roles),)),
                    Err(e) => Ok((Err(e),)),
                }
            }

            #[cfg(not(feature = "app-auth"))]
            {
                let _ = user_id;
                Ok((Err("role management requires app-auth feature".into()),))
            }
        },
    )?;

    // ── set-user-roles ─────────────────────────────────────────────
    inst.func_wrap(
        "set-user-roles",
        |store: StoreContextMut<'_, AppContext>, (user_id, roles): (String, Vec<String>)| -> wasmtime::Result<(Result<String, String>,)> {
            let ctx = store.data();

            if !ctx.caller_roles.contains(&"admin".to_string()) {
                return Ok((Err("requires 'admin' role".into()),));
            }

            #[cfg(feature = "app-auth")]
            {
                match enclave_os_app_auth::set_user_roles(&ctx.sealed_kv, &user_id, &roles) {
                    Ok(()) => Ok((Ok(format!("roles updated for '{user_id}'")),)),
                    Err(e) => Ok((Err(e),)),
                }
            }

            #[cfg(not(feature = "app-auth"))]
            {
                let _ = (user_id, roles);
                Ok((Err("role management requires app-auth feature".into()),))
            }
        },
    )?;

    // ── remove-user-roles ──────────────────────────────────────────
    inst.func_wrap(
        "remove-user-roles",
        |store: StoreContextMut<'_, AppContext>, (user_id,): (String,)| -> wasmtime::Result<(Result<String, String>,)> {
            let ctx = store.data();

            if !ctx.caller_roles.contains(&"admin".to_string()) {
                return Ok((Err("requires 'admin' role".into()),));
            }

            #[cfg(feature = "app-auth")]
            {
                match enclave_os_app_auth::remove_user_roles(&ctx.sealed_kv, &user_id) {
                    Ok(()) => Ok((Ok(format!("roles removed for '{user_id}'")),)),
                    Err(e) => Ok((Err(e),)),
                }
            }

            #[cfg(not(feature = "app-auth"))]
            {
                let _ = user_id;
                Ok((Err("role management requires app-auth feature".into()),))
            }
        },
    )?;

    Ok(())
}

/// Check if the caller has at least one of the required roles.
fn has_any_role(caller_roles: &[String], required: &[&str]) -> bool {
    caller_roles.iter().any(|r| required.contains(&r.as_str()))
}
