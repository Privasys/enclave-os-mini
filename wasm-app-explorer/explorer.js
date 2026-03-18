/* WASM App Explorer — standalone attestation & API testing */
(function () {
    'use strict';

    // ── State ──────────────────────────────────────
    let baseUrl = '';
    let appName = '';
    let currentTab = 'attestation';

    // Attestation state
    let attestResult = null;
    let attestLoading = false;
    let challenge = generateHex(32);
    let verifyResult = null;
    let verifyDebug = null;

    // API state
    let schema = null;
    let schemaLoading = false;
    let schemaError = null;
    let selectedFunc = '';
    let paramValues = {};
    let rpcResponse = null;
    let rpcStatus = null;
    let rpcElapsed = null;
    let rpcError = null;
    let rpcSending = false;
    let history = [];
    let historyId = 0;

    // ── Helpers ────────────────────────────────────
    function $(sel, ctx) { return (ctx || document).querySelector(sel); }
    function $$(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }
    function h(tag, attrs, ...children) {
        const el = document.createElement(tag);
        if (attrs) for (const [k, v] of Object.entries(attrs)) {
            if (k === 'className') el.className = v;
            else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
            else if (k === 'html') el.innerHTML = v;
            else el.setAttribute(k, v);
        }
        for (const c of children.flat(Infinity)) {
            if (c == null || c === false) continue;
            el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
        }
        return el;
    }

    function generateHex(bytes) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToText(hex) {
        try {
            const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            if (/^[\x20-\x7e]+$/.test(text)) return text;
            return null;
        } catch { return null; }
    }

    function copyText(text) {
        navigator.clipboard.writeText(text).catch(() => {});
    }

    async function apiFetch(path, opts) {
        const url = baseUrl.replace(/\/+$/, '') + path;
        const res = await fetch(url, {
            ...opts,
            headers: { 'Content-Type': 'application/json', ...opts?.headers }
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({ error: res.statusText }));
            throw new Error(body.error || `HTTP ${res.status}`);
        }
        if (res.status === 204) return null;
        return res.json();
    }

    const TEXT_OIDS = new Set(['1.3.6.1.4.1.65230.3.3', '1.3.6.1.4.1.65230.3.4']);
    const OID_DESCRIPTIONS = {
        'Config Merkle Root': 'Hash of the enclave configuration tree.',
        'Egress CA Hash': 'Hash of the CA certificate used for egress TLS.',
        'Runtime Version Hash': 'Hash identifying the runtime version inside the enclave.',
        'Combined Workloads Hash': 'Aggregate hash of all loaded WASM workloads.',
        'DEK Origin': 'Data Encryption Key origin.',
        'Attestation Servers Hash': 'Hash of the trusted attestation server list.',
        'Workload Config Merkle Root': 'Merkle root of this workload\'s configuration.',
        'Workload Code Hash': 'SHA-256 hash of the compiled WASM bytecode.',
        'Workload Image Ref': 'Container image reference.',
        'Workload Key Source': 'How the workload\'s encryption keys are sourced.',
        'Workload Permissions Hash': 'Hash of the security permissions granted to this workload.'
    };

    // ── WIT types ──────────────────────────────────
    function witTypeLabel(ty) {
        if (!ty) return '?';
        switch (ty.kind) {
            case 'string': case 'bool': case 'char':
            case 'u8': case 'u16': case 'u32': case 'u64':
            case 's8': case 's16': case 's32': case 's64':
            case 'f32': case 'f64': case 'float32': case 'float64':
                return ty.kind.replace('float32', 'f32').replace('float64', 'f64');
            case 'list': return ty.element ? `list<${witTypeLabel(ty.element)}>` : 'list';
            case 'option': return ty.inner ? `option<${witTypeLabel(ty.inner)}>` : 'option';
            case 'result': return `result<${ty.ok ? witTypeLabel(ty.ok) : '_'}, ${ty.err ? witTypeLabel(ty.err) : '_'}>`;
            case 'record': return 'record';
            case 'tuple': return ty.elements ? `tuple<${ty.elements.map(witTypeLabel).join(', ')}>` : 'tuple';
            case 'variant': return 'variant';
            case 'enum': return ty.names ? `enum{${ty.names.join('|')}}` : 'enum';
            case 'flags': return 'flags';
            default: return ty.kind;
        }
    }

    function defaultValue(ty) {
        if (!ty) return '';
        switch (ty.kind) {
            case 'string': case 'char': return '';
            case 'bool': return false;
            case 'u8': case 'u16': case 'u32': case 'u64':
            case 's8': case 's16': case 's32': case 's64':
            case 'f32': case 'f64': case 'float32': case 'float64': return 0;
            case 'list': return [];
            case 'option': return null;
            case 'record':
                if (ty.fields) {
                    const o = {};
                    for (const f of ty.fields) o[f.name] = defaultValue(f.type);
                    return o;
                }
                return {};
            default: return '';
        }
    }

    // ── Connect ────────────────────────────────────
    function handleConnect() {
        const fullInput = $('#endpoint-input').value.trim();
        const baseInput = $('#base-url-input') ? $('#base-url-input').value.trim() : '';
        const nameInput = $('#app-name-input') ? $('#app-name-input').value.trim() : '';

        // Option 1: full URL like https://host/api/v1/apps/my-app
        if (fullInput) {
            const match = fullInput.match(/^(https?:\/\/[^/]+(?:\/[^/]+)*?)\/api\/v1\/apps\/([^/?#]+)\/?$/i);
            if (match) {
                baseUrl = match[1];
                appName = decodeURIComponent(match[2]);
            } else {
                // Treat as base URL, combine with name field
                baseUrl = fullInput;
                appName = nameInput;
            }
        }
        // Option 2: separate base URL + app name
        else if (baseInput && nameInput) {
            baseUrl = baseInput;
            appName = nameInput;
        }

        if (!baseUrl || !appName) {
            alert('Provide a base URL and app name.\n\nExamples:\n  - https://api.developer.privasys.org/api/v1/apps/wasm-app-example\n  - Base URL: https://api.developer.privasys.org  +  App: wasm-app-example');
            return;
        }

        document.body.classList.add('connected');
        $('#connection-info').textContent = `${appName} — ${baseUrl}`;
        renderTabs();
        switchTab('attestation');
    }

    // ── Tab switching ──────────────────────────────
    function switchTab(tab) {
        currentTab = tab;
        $$('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
        if (tab === 'attestation') renderAttestation();
        else if (tab === 'api') renderApiTesting();
    }

    function renderTabs() {
        const container = $('#tab-container');
        container.innerHTML = '';
        container.appendChild(h('div', { className: 'tabs' },
            h('button', { className: 'tab-btn active', 'data-tab': 'attestation', onClick: () => switchTab('attestation') }, 'Attestation'),
            h('button', { className: 'tab-btn', 'data-tab': 'api', onClick: () => switchTab('api') }, 'API Testing')
        ));
        container.appendChild(h('div', { id: 'tab-content' }));
    }

    // ═══════════════════════════════════════════════
    // ATTESTATION TAB
    // ═══════════════════════════════════════════════

    async function doAttest() {
        attestLoading = true;
        attestResult = null;
        verifyResult = null;
        verifyDebug = null;
        renderAttestation();
        try {
            const trimmed = challenge.trim();
            if (trimmed && !/^[0-9a-fA-F]{32,128}$/.test(trimmed)) {
                throw new Error('Challenge must be 32-128 hex characters');
            }
            const qs = trimmed ? `?challenge=${encodeURIComponent(trimmed)}` : '';
            const data = await apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/attest${qs}`);
            attestResult = data;
            attestLoading = false;
            renderAttestation();
            if (data.challenge_mode && data.quote?.report_data && data.certificate?.public_key_sha256 && data.challenge) {
                await verifyReportData();
            }
        } catch (e) {
            attestLoading = false;
            attestResult = null;
            renderAttestation();
            alert('Attestation failed: ' + e.message);
        }
    }

    async function verifyReportData() {
        if (!attestResult) return;
        const r = attestResult;
        try {
            const pkHex = r.certificate.public_key_sha256;
            const ch = r.challenge;
            const pubKeySha256 = new Uint8Array(pkHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const nonce = new Uint8Array(ch.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const concat = new Uint8Array(pubKeySha256.length + nonce.length);
            concat.set(pubKeySha256);
            concat.set(nonce, pubKeySha256.length);
            const hash = await crypto.subtle.digest('SHA-512', concat);
            const computed = Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
            const actual = r.quote.report_data.toLowerCase();
            verifyDebug = { computed, actual };
            verifyResult = computed === actual ? 'match' : 'mismatch';
        } catch {
            verifyResult = 'error';
        }
        renderAttestation();
    }

    function renderAttestation() {
        const content = $('#tab-content');
        if (!content) return;
        content.innerHTML = '';

        if (!attestResult) {
            // Show challenge form
            const wrap = h('div', null,
                h('div', { className: 'empty-state' },
                    h('div', { className: 'icon' }, '🛡'),
                    h('h3', null, 'Remote Attestation'),
                    h('p', null, 'Connect to the enclave via RA-TLS and inspect the x.509 certificate, SGX quote, and attestation extensions.')
                ),
                h('div', { className: 'challenge-input-group' },
                    h('label', null, 'Challenge Nonce'),
                    h('div', { className: 'row' },
                        h('input', { id: 'challenge-input', type: 'text', value: challenge, maxLength: '128', placeholder: '32-128 hex chars', onInput: e => { challenge = e.target.value.replace(/[^0-9a-fA-F]/g, ''); } }),
                        h('button', { className: 'btn btn-outline btn-sm', onClick: () => { challenge = generateHex(32); $('#challenge-input').value = challenge; } }, 'Regenerate')
                    ),
                    h('div', { className: 'hint' }, 'Random nonce to prove the certificate was generated for this request. Leave empty for deterministic mode.')
                ),
                h('div', { className: 'text-center mt-4' },
                    attestLoading
                        ? h('span', { className: 'flex items-center gap-2', style: 'justify-content:center' }, h('span', { className: 'loading-spinner' }), ' Connecting…')
                        : h('button', { className: 'btn', onClick: doAttest }, 'Inspect Certificate')
                )
            );
            content.appendChild(wrap);
            return;
        }

        const r = attestResult;
        const els = [];

        // Challenge banner
        if (r.challenge_mode && r.challenge) {
            const color = verifyResult === 'match' ? 'emerald' : verifyResult === 'mismatch' || verifyResult === 'error' ? 'red' : 'amber';
            const badgeText = verifyResult === 'match' ? '✓ Match — freshness verified' : verifyResult === 'mismatch' ? '✗ Mismatch' : verifyResult === 'error' ? '✗ Error' : 'Verifying…';
            const badgeCls = verifyResult === 'match' ? 'badge-ok' : verifyResult === 'mismatch' || verifyResult === 'error' ? 'badge-err' : 'badge-warn';
            els.push(h('div', { className: `card card-${color === 'emerald' ? 'emerald' : ''}`, style: color === 'red' ? 'border-color:rgba(220,38,38,0.3);background:rgba(220,38,38,0.04)' : color === 'amber' ? 'border-color:rgba(217,119,6,0.3);background:rgba(217,119,6,0.04)' : '' },
                h('div', { className: 'card-body' },
                    h('div', { className: 'flex items-center gap-2 mb-2' },
                        h('span', null, '🔐'),
                        h('strong', { className: 'text-xs' }, 'Challenge Mode Active'),
                        h('span', { className: `badge ${badgeCls}` }, badgeText)
                    ),
                    h('div', { className: 'text-xxs text-muted mb-2' }, 'This certificate was freshly generated in response to your challenge nonce.'),
                    h('div', { className: 'text-xxs text-muted' }, 'Challenge sent:'),
                    h('div', { className: 'field-value', style: 'font-size:11px' }, r.challenge)
                )
            ));
        } else if (r.challenge_mode === false) {
            els.push(h('div', { className: 'card' },
                h('div', { className: 'card-body text-center text-xxs text-muted' },
                    h('strong', null, 'Deterministic mode'), ' — certificate may be reused across connections. Use challenge mode for freshness.'
                )
            ));
        }

        // Actions
        els.push(h('div', { className: 'actions-bar' },
            h('button', { className: 'btn btn-outline btn-sm', onClick: doAttest }, attestLoading ? 'Refreshing…' : 'Refresh'),
            h('button', { className: 'btn btn-outline btn-sm', onClick: () => downloadBlob(r.pem, 'enclave-certificate.pem', 'application/x-pem-file') }, 'Download PEM'),
            h('button', { className: 'btn btn-outline btn-sm', style: 'margin-left:auto', onClick: () => { attestResult = null; verifyResult = null; challenge = generateHex(32); renderAttestation(); } }, 'New Challenge')
        ));

        // TLS
        els.push(renderCard('TLS Connection', null, [
            renderField('Protocol', r.tls.version),
            renderField('Cipher Suite', r.tls.cipher_suite)
        ]));

        // Certificate
        els.push(renderCard('x.509 Certificate', null, [
            { label: 'Subject', value: r.certificate.subject, desc: 'The entity this certificate identifies.' },
            { label: 'Issuer', value: r.certificate.issuer, desc: 'Certificate authority that issued the cert.' },
            { label: 'Serial Number', value: r.certificate.serial_number },
            { label: 'Valid From', value: r.certificate.not_before },
            { label: 'Valid Until', value: r.certificate.not_after },
            { label: 'Signature Algorithm', value: r.certificate.signature_algorithm },
            { label: 'Public Key SHA-256', value: r.certificate.public_key_sha256, desc: 'SHA-256 fingerprint of the public key.' }
        ].map(f => renderField(f.label, f.value, f.desc))));

        // SGX Quote
        if (r.quote) {
            const quoteFields = [
                { label: 'Quote Type', value: r.quote.type },
                r.quote.format && { label: 'Format', value: r.quote.format },
                r.quote.version != null && { label: 'Version', value: String(r.quote.version) },
                r.quote.mr_enclave && { label: 'MRENCLAVE', value: r.quote.mr_enclave, desc: 'Hash of the enclave binary. Uniquely identifies the build.' },
                r.quote.mr_signer && { label: 'MRSIGNER', value: r.quote.mr_signer, desc: 'Hash of the signer\'s public key.' },
                r.quote.report_data && { label: 'Report Data', value: r.quote.report_data, desc: r.challenge_mode ? 'SHA-512(SHA-256(pubkey) ‖ challenge). A match proves freshness.' : 'SHA-512(SHA-256(pubkey) ‖ timestamp).' },
                { label: 'OID', value: r.quote.oid }
            ].filter(Boolean);
            const quoteEls = quoteFields.map(f => {
                const el = renderField(f.label, f.value, f.desc);
                if (f.label === 'Report Data' && verifyResult) {
                    const badge = verifyResult === 'match'
                        ? h('span', { className: 'badge badge-ok mt-2' }, '✓ Verified')
                        : h('span', { className: 'badge badge-err mt-2' }, '✗ ' + (verifyResult === 'mismatch' ? 'Mismatch' : 'Error'));
                    el.appendChild(badge);
                }
                return el;
            });
            if (r.quote.is_mock) {
                quoteEls.unshift(h('span', { className: 'badge badge-warn' }, 'Mock'));
            }
            els.push(renderCard('SGX Quote', null, quoteEls));
        }

        // Platform extensions
        if (r.extensions && r.extensions.length > 0) {
            els.push(renderExtCard('Platform Attestation Extensions', 'Platform-level x.509 extensions (OIDs 1.x/2.x) from the enclave certificate.', r.extensions, false, r));
        }

        // Workload extensions
        if (r.app_extensions && r.app_extensions.length > 0) {
            els.push(renderExtCard('Workload Attestation Extensions', 'Per-workload x.509 extensions (OIDs 3.x) via SNI routing.', r.app_extensions, true, r));
        }

        // PEM
        if (r.pem) els.push(renderPemCard('Platform PEM Certificate', r.pem));
        if (r.app_pem) els.push(renderPemCard('Workload PEM Certificate', r.app_pem, true));

        for (const el of els) content.appendChild(el);
    }

    function renderCard(title, desc, children) {
        return h('div', { className: 'card' },
            h('div', { className: 'card-header' }, h('h3', null, title)),
            h('div', { className: 'card-body' },
                desc ? h('p', null, desc) : null,
                ...children
            )
        );
    }

    function renderField(label, value, desc) {
        return h('div', { className: 'field' },
            h('div', { className: 'field-label' },
                h('span', null, label),
                h('button', { className: 'copy-btn', onClick: () => copyText(value) }, '⧉')
            ),
            h('div', { className: 'field-value' }, value || '—'),
            desc ? h('div', { className: 'field-desc' }, desc) : null
        );
    }

    function renderExtCard(title, desc, exts, emerald, result) {
        const items = exts.map(ext => {
            const text = TEXT_OIDS.has(ext.oid) ? hexToText(ext.value_hex) : null;
            const item = h('div', { className: 'ext-item' },
                h('div', { className: 'flex items-center gap-2' },
                    h('span', { className: 'ext-label' }, ext.label),
                    h('button', { className: 'copy-btn', onClick: () => copyText(ext.value_hex) }, '⧉')
                ),
                h('div', { className: 'field-value' },
                    text
                        ? h('span', null, h('span', { style: 'opacity:0.9' }, text), ' ', h('span', { style: 'opacity:0.3;font-size:10px' }, `(${ext.value_hex})`))
                        : ext.value_hex
                ),
                h('div', { className: 'ext-oid' }, ext.oid),
                OID_DESCRIPTIONS[ext.label] ? h('div', { className: 'field-desc' }, OID_DESCRIPTIONS[ext.label]) : null
            );
            // Code hash verification
            if (ext.oid === '1.3.6.1.4.1.65230.3.2' && result && result.cwasm_hash) {
                const match = ext.value_hex.toLowerCase() === result.cwasm_hash.toLowerCase();
                item.appendChild(h('div', { className: 'mt-2' },
                    h('span', { className: `badge ${match ? 'badge-ok' : 'badge-err'}` },
                        match ? '✓ Verified — matches uploaded CWASM hash' : '✗ Mismatch'
                    )
                ));
            }
            return item;
        });
        return h('div', { className: `card ${emerald ? 'card-emerald' : ''}` },
            h('div', { className: 'card-header' }, h('h3', null, title)),
            h('div', { className: 'card-body' }, desc ? h('p', null, desc) : null, ...items)
        );
    }

    function renderPemCard(title, pem, emerald) {
        return h('div', { className: `card ${emerald ? 'card-emerald' : ''}` },
            h('div', { className: 'card-header' },
                h('h3', null, title),
                h('div', { className: 'flex gap-2' },
                    h('button', { className: 'copy-btn', onClick: () => downloadBlob(pem, title.includes('Workload') ? 'workload-certificate.pem' : 'enclave-certificate.pem', 'application/x-pem-file') }, 'Download'),
                    h('button', { className: 'copy-btn', onClick: () => copyText(pem) }, 'Copy')
                )
            ),
            h('div', { className: 'card-body' }, h('pre', { className: 'pem-block' }, pem))
        );
    }

    function downloadBlob(text, name, type) {
        const blob = new Blob([text], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ═══════════════════════════════════════════════
    // API TESTING TAB
    // ═══════════════════════════════════════════════

    function getAllFunctions(s) {
        const fns = [...(s.functions || [])];
        if (s.interfaces) {
            for (const iface of s.interfaces) {
                for (const f of iface.functions) {
                    fns.push({ ...f, name: `${iface.name}.${f.name}` });
                }
            }
        }
        return fns;
    }

    function getSelectedFunction() {
        if (!schema) return null;
        return getAllFunctions(schema).find(f => f.name === selectedFunc) || null;
    }

    function initParams(fn) {
        paramValues = {};
        if (fn) for (const p of fn.params) paramValues[p.name] = defaultValue(p.type);
    }

    async function loadSchema() {
        schemaLoading = true;
        schemaError = null;
        schema = null;
        renderApiTesting();
        try {
            const resp = await apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/schema`);
            if (resp.status !== 'schema') throw new Error(resp.message || 'Failed to fetch schema');
            schema = resp.schema;
            const fns = getAllFunctions(schema);
            if (fns.length > 0) {
                selectedFunc = fns[0].name;
                initParams(fns[0]);
            }
        } catch (e) {
            schemaError = e.message;
        } finally {
            schemaLoading = false;
            renderApiTesting();
        }
    }

    async function sendRpc() {
        const fn = getSelectedFunction();
        if (!fn || rpcSending) return;
        rpcSending = true;
        rpcResponse = null;
        rpcStatus = null;
        rpcError = null;
        rpcElapsed = null;
        renderApiTesting();
        const start = performance.now();
        try {
            const data = await apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/rpc/${encodeURIComponent(fn.name)}`, {
                method: 'POST',
                body: JSON.stringify(paramValues)
            });
            const ms = Math.round(performance.now() - start);
            const json = JSON.stringify(data, null, 2);
            rpcElapsed = ms;
            rpcResponse = json;
            rpcStatus = 'ok';
            history.unshift({ id: historyId++, func: fn.name, params: { ...paramValues }, response: json, status: 'ok', elapsed: ms, timestamp: new Date() });
            if (history.length > 20) history.length = 20;
        } catch (e) {
            const ms = Math.round(performance.now() - start);
            rpcElapsed = ms;
            rpcError = e.message;
            rpcStatus = 'error';
            history.unshift({ id: historyId++, func: fn.name, params: { ...paramValues }, response: e.message, status: 'error', elapsed: ms, timestamp: new Date() });
            if (history.length > 20) history.length = 20;
        } finally {
            rpcSending = false;
            renderApiTesting();
        }
    }

    function renderApiTesting() {
        const content = $('#tab-content');
        if (!content) return;
        content.innerHTML = '';

        if (!schema && !schemaLoading && !schemaError) {
            // first load
            loadSchema();
            return;
        }

        if (schemaLoading) {
            content.appendChild(h('div', { className: 'empty-state' },
                h('span', { className: 'loading-spinner' }),
                h('p', { className: 'mt-2' }, 'Discovering API schema…')
            ));
            return;
        }

        if (schemaError) {
            content.appendChild(h('div', { className: 'empty-state' },
                h('div', { className: 'icon' }, '⚠'),
                h('h3', null, 'Could not load API schema'),
                h('p', null, schemaError),
                h('button', { className: 'btn btn-sm mt-4', onClick: loadSchema }, 'Retry')
            ));
            return;
        }

        const allFuncs = getAllFunctions(schema);
        if (allFuncs.length === 0) {
            content.appendChild(h('div', { className: 'empty-state' },
                h('div', { className: 'icon' }, '📦'),
                h('h3', null, 'No exported functions'),
                h('p', null, 'Ensure a WASM component with exports is deployed.')
            ));
            return;
        }

        const fn = getSelectedFunction();

        // Request builder card
        const selectEl = h('select', { className: 'rpc-select', onChange: e => { selectedFunc = e.target.value; const f = getAllFunctions(schema).find(x => x.name === e.target.value); initParams(f); rpcResponse = null; rpcStatus = null; rpcError = null; renderApiTesting(); } });
        for (const f of allFuncs) {
            const opt = h('option', { value: f.name }, `/rpc/${schema.name}/${f.name}`);
            if (f.name === selectedFunc) opt.selected = true;
            selectEl.appendChild(opt);
        }

        // Signature
        let sigEl = null;
        if (fn) {
            const parts = [
                h('span', { className: 'sig-kw' }, 'fn'),
                ' ',
                h('span', { className: 'sig-fn' }, fn.name),
                h('span', { className: 'sig-sep' }, '(')
            ];
            fn.params.forEach((p, i) => {
                if (i > 0) parts.push(h('span', { className: 'sig-sep' }, ', '));
                parts.push(h('span', { className: 'sig-pname' }, p.name), h('span', { className: 'sig-sep' }, ': '), h('span', { className: 'sig-type' }, witTypeLabel(p.type)));
            });
            parts.push(h('span', { className: 'sig-sep' }, ')'));
            if (fn.results.length > 0) {
                parts.push(h('span', { className: 'sig-sep' }, ' → '));
                fn.results.forEach((r, i) => {
                    if (i > 0) parts.push(h('span', { className: 'sig-sep' }, ', '));
                    parts.push(h('span', { className: 'sig-ret' }, witTypeLabel(r.type)));
                });
            }
            sigEl = h('div', { className: 'sig-bar' }, ...parts);
        }

        // Params
        const paramsEl = h('div', { className: 'params-section' });
        if (fn && fn.params.length > 0) {
            paramsEl.appendChild(h('div', { className: 'params-label' }, 'Parameters'));
            for (const p of fn.params) {
                const row = h('div', { className: 'param-row' },
                    h('div', { className: 'param-info' },
                        h('div', { className: 'param-name' }, p.name),
                        h('div', { className: 'param-type' }, witTypeLabel(p.type))
                    )
                );
                row.appendChild(createParamInput(p));
                paramsEl.appendChild(row);
            }
        } else {
            paramsEl.appendChild(h('div', { className: 'text-xs text-muted', style: 'padding:8px 0' }, 'This function takes no parameters'));
        }

        const requestCard = h('div', { className: 'card' },
            h('div', { className: 'rpc-bar' },
                h('div', { className: 'rpc-method' }, 'POST'),
                selectEl,
                h('button', { className: 'rpc-send', disabled: rpcSending || !selectedFunc, onClick: sendRpc },
                    rpcSending ? h('span', { className: 'loading-spinner', style: 'width:14px;height:14px;border-width:2px' }) : 'Send'
                )
            ),
            sigEl,
            paramsEl,
            h('div', { className: 'shortcut-hint' }, 'Press ', h('kbd', null, 'Ctrl+Enter'), ' to send')
        );
        content.appendChild(requestCard);

        // Response
        if (rpcResponse || rpcError) {
            const resCard = h('div', { className: 'card' },
                h('div', { className: 'card-header' },
                    h('div', { className: 'response-header' },
                        h('span', { className: 'label' }, 'Response'),
                        rpcStatus === 'ok' ? h('span', { className: 'flex items-center gap-2' }, h('span', { className: 'dot dot-ok' }), h('span', { className: 'text-xxs', style: 'color:var(--emerald);font-weight:500' }, '200 OK')) : null,
                        rpcStatus === 'error' ? h('span', { className: 'flex items-center gap-2' }, h('span', { className: 'dot dot-err' }), h('span', { className: 'text-xxs', style: 'color:var(--red);font-weight:500' }, 'Error')) : null,
                        rpcElapsed != null ? h('span', { className: 'meta' }, rpcElapsed + 'ms') : null
                    ),
                    h('button', { className: 'copy-btn', onClick: () => copyText(rpcResponse || rpcError || '') }, 'Copy')
                ),
                rpcError
                    ? h('div', { className: 'response-error' }, rpcError)
                    : h('pre', { className: 'response-body' }, rpcResponse)
            );
            content.appendChild(resCard);
        }

        // History
        if (history.length > 0) {
            const historyItems = history.map(entry =>
                h('button', { className: 'history-item', onClick: () => loadHistoryEntry(entry) },
                    h('span', { className: `dot ${entry.status === 'ok' ? 'dot-ok' : 'dot-err'}` }),
                    h('span', { className: 'history-fn' }, entry.func),
                    h('span', { className: 'history-ms' }, entry.elapsed + 'ms'),
                    h('span', { className: 'history-time' }, entry.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))
                )
            );
            content.appendChild(h('div', { className: 'card' },
                h('div', { className: 'card-header' },
                    h('h3', null, 'History'),
                    h('button', { className: 'copy-btn', onClick: () => { history = []; renderApiTesting(); } }, 'Clear')
                ),
                h('div', { style: 'max-height:200px;overflow-y:auto' }, ...historyItems)
            ));
        }
    }

    function createParamInput(p) {
        const ty = p.type;
        switch (ty.kind) {
            case 'bool': {
                const track = h('button', { className: `toggle-track ${paramValues[p.name] ? 'on' : 'off'}`, onClick: () => { paramValues[p.name] = !paramValues[p.name]; renderApiTesting(); } },
                    h('span', { className: 'toggle-thumb' })
                );
                return h('div', { className: 'flex items-center gap-2' }, track, h('span', { className: 'text-xs text-muted' }, String(!!paramValues[p.name])));
            }
            case 'u8': case 'u16': case 'u32': case 'u64':
            case 's8': case 's16': case 's32': case 's64':
            case 'f32': case 'f64': case 'float32': case 'float64':
                return h('input', { type: 'number', className: 'param-input', value: String(paramValues[p.name] || 0), placeholder: '0', onInput: e => { paramValues[p.name] = ty.kind.startsWith('f') || ty.kind.startsWith('float') ? parseFloat(e.target.value) || 0 : parseInt(e.target.value) || 0; } });
            case 'enum': {
                const sel = h('select', { className: 'param-input', onChange: e => { paramValues[p.name] = e.target.value; } });
                for (const n of (ty.names || [])) { const o = h('option', { value: n }, n); if (paramValues[p.name] === n) o.selected = true; sel.appendChild(o); }
                return sel;
            }
            case 'string': case 'char':
                return h('input', { type: 'text', className: 'param-input', value: String(paramValues[p.name] ?? ''), placeholder: ty.kind === 'char' ? 'single character' : `Enter ${p.name}…`, onInput: e => { paramValues[p.name] = e.target.value; } });
            default: {
                const val = typeof paramValues[p.name] === 'string' ? paramValues[p.name] : JSON.stringify(paramValues[p.name], null, 2);
                return h('textarea', { className: 'param-input', rows: '3', spellcheck: 'false', placeholder: 'JSON value', onInput: e => { try { paramValues[p.name] = JSON.parse(e.target.value); } catch { paramValues[p.name] = e.target.value; } } }, val);
            }
        }
    }

    function loadHistoryEntry(entry) {
        selectedFunc = entry.func;
        paramValues = { ...entry.params };
        rpcResponse = entry.response;
        rpcStatus = entry.status;
        rpcElapsed = entry.elapsed;
        rpcError = entry.status === 'error' ? entry.response : null;
        renderApiTesting();
    }

    // ── Keyboard shortcut ──────────────────────────
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (currentTab === 'api' && schema) sendRpc();
        }
    });

    // ── Init ───────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        $('#connect-btn').addEventListener('click', handleConnect);
        // Enter key on any connect-screen input triggers connect
        for (const id of ['endpoint-input', 'base-url-input', 'app-name-input']) {
            const el = $('#' + id);
            if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') handleConnect(); });
        }
    });
})();
