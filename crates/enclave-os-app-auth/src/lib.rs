// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Per-app role-based access control for enclave-os WASM apps.
//!
//! Stores user roles in the app's own sealed KV space (same table as the
//! app's WASI filesystem, differentiated by the `roles:` key prefix).
//! The store never confers `admin`: that comes only from the identity
//! provider's `roles` claim.

pub mod roles;

pub use roles::{
    get_default_roles,
    get_or_enroll_user_roles,
    get_user_roles,
    list_users,
    remove_user_roles,
    set_default_roles,
    set_user_roles,
    validate_user_handle,
};
