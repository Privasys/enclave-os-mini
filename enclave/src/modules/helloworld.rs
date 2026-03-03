// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HelloWorld example module.

use enclave_os_common::protocol::{Request, Response};
use crate::modules::{EnclaveModule, RequestContext};

pub struct HelloWorldModule;

impl EnclaveModule for HelloWorldModule {
    fn name(&self) -> &str { "helloworld" }

    fn handle(&self, req: &Request, _ctx: &RequestContext) -> Option<Response> {
        match req {
            Request::Data(payload) if payload == b"hello" => {
                Some(Response::Data(b"world".to_vec()))
            }
            _ => None,
        }
    }
}
