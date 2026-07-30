// Simply Hook Executor SPA Client
// No external dependencies (Vanilla JS)

// Reusable searchable dropdown ("combobox"): a text input plus a live-filtered option list.
// Two modes, chosen by whether searchId and valueId are the same element:
//   - allowFreeText: true  — searchId === valueId; the input's own text IS the value (used by
//     the execution history's hook filter, which the API resolves by name or UUID). The dropdown
//     is purely a convenience of known-hook suggestions; typing anything not listed still works.
//   - allowFreeText: false — searchId !== valueId; the search input only displays a label, and
//     valueId (a hidden input) only changes when the user actually picks a listed option. Typing
//     without picking a fresh option clears the hidden value, so a stale prior selection can
//     never be silently resubmitted alongside now-mismatched displayed text.
class SearchableSelect {
    constructor({ rootId, searchId, valueId, allowFreeText = false, emptyText = 'No matches', onSelect }) {
        this.root = document.getElementById(rootId);
        this.search = document.getElementById(searchId);
        this.valueInput = document.getElementById(valueId);
        this.menu = this.root.querySelector('.combobox-menu');
        this.allowFreeText = allowFreeText;
        this.emptyText = emptyText;
        this.onSelect = onSelect || (() => {});
        this.options = [];

        this.search.addEventListener('input', () => {
            if (!this.allowFreeText) {
                this.valueInput.value = '';
            }
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('focus', () => {
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeMenu();
            } else if (e.key === 'Enter') {
                const first = this.menu.querySelector('.combobox-option');
                if (first) {
                    e.preventDefault();
                    first.dispatchEvent(new MouseEvent('mousedown'));
                }
            }
        });
        document.addEventListener('click', (e) => {
            if (!this.root.contains(e.target)) this.closeMenu();
        });
    }

    // options: [{ value, label }]
    setOptions(options) {
        this.options = options;
        // Keep an already-selected strict value's displayed label in sync if the underlying
        // list changed (e.g. a hook was renamed) while this control wasn't being edited.
        if (!this.allowFreeText && this.valueInput.value) {
            const current = this.options.find(o => String(o.value) === this.valueInput.value);
            if (current) this.search.value = current.label;
        }
    }

    renderMenu(filterText) {
        const q = (filterText || '').trim().toLowerCase();
        const filtered = this.options.filter(o => o.label.toLowerCase().includes(q));
        if (filtered.length === 0) {
            this.menu.innerHTML = `<div class="combobox-empty">${escapeHtml(this.emptyText)}</div>`;
            return;
        }
        this.menu.innerHTML = filtered.map((o, i) =>
            `<div class="combobox-option" data-index="${i}">${escapeHtml(o.label)}</div>`
        ).join('');
        this.menu.querySelectorAll('.combobox-option').forEach((el, i) => {
            // mousedown (not click) with preventDefault: fires before — and suppresses — the
            // search input's own blur, so the selection always registers on the first press
            // instead of the menu disappearing out from under the click.
            el.addEventListener('mousedown', (e) => {
                e.preventDefault();
                this.select(filtered[i]);
            });
        });
    }

    select(opt) {
        this.search.value = opt.label;
        if (this.valueInput !== this.search) {
            this.valueInput.value = opt.value;
        }
        this.onSelect(opt.value);
        this.closeMenu();
    }

    openMenu() {
        this.menu.classList.remove('hidden');
    }

    closeMenu() {
        this.menu.classList.add('hidden');
    }
}

// Client-side cache for a paginated list endpoint: fetches large chunks from the server
// (chunkSize, e.g. 100 items) but paginates locally in small pages (pageSize, e.g. 15) — most
// "Next"/"Prev" clicks are then a pure client-side slice with no network round-trip at all.
// Background-prefetches the next server chunk as soon as the user reaches the second-to-last
// local page of whatever's currently cached.
class PagedCache {
    constructor({ chunkSize = 100, pageSize = 15, fetchChunk }) {
        this.chunkSize = chunkSize;
        this.pageSize = pageSize;
        this.fetchChunk = fetchChunk; // async (serverOffset, chunkSize) => Array<item>
        this.reset();
    }

    reset() {
        this.items = [];
        this.serverOffset = 0;
        this.hasMoreOnServer = true;
        this.localPage = 0;
        this.prefetching = null; // in-flight prefetch promise, if any
    }

    get totalLocalPages() {
        return Math.max(1, Math.ceil(this.items.length / this.pageSize));
    }

    get currentPageItems() {
        const start = this.localPage * this.pageSize;
        return this.items.slice(start, start + this.pageSize);
    }

    get hasNextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        return nextPageStart < this.items.length || this.hasMoreOnServer;
    }

    get hasPrevPage() {
        return this.localPage > 0;
    }

    // Discards everything cached and fetches a fresh first chunk — used on initial load and
    // whenever the active filters change (a different query is a different dataset, not more
    // pages of the old one).
    async loadFirstChunk() {
        this.reset();
        const chunk = await this.fetchChunk(0, this.chunkSize);
        this.items = chunk;
        this.serverOffset = chunk.length;
        this.hasMoreOnServer = chunk.length === this.chunkSize;
        this._maybePrefetch();
    }

    async fetchNextChunk() {
        if (!this.hasMoreOnServer) return;
        if (this.prefetching) return this.prefetching;
        this.prefetching = (async () => {
            const chunk = await this.fetchChunk(this.serverOffset, this.chunkSize);
            this.items = [...this.items, ...chunk];
            this.serverOffset += chunk.length;
            this.hasMoreOnServer = chunk.length === this.chunkSize;
            this.prefetching = null;
        })();
        return this.prefetching;
    }

    async nextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        if (nextPageStart >= this.items.length && this.hasMoreOnServer) {
            await this.fetchNextChunk();
        }
        if (nextPageStart < this.items.length) {
            this.localPage++;
        }
        this._maybePrefetch();
    }

    prevPage() {
        if (this.localPage > 0) this.localPage--;
    }

    // Fires a background fetch the moment the user lands on the second-to-last page of the
    // currently cached chunk — re-evaluated off the live item count, so it correctly fires again
    // after each new chunk arrives.
    _maybePrefetch() {
        if (!this.hasMoreOnServer || this.prefetching) return;
        if (this.localPage === this.totalLocalPages - 2) {
            this.fetchNextChunk();
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Pure-JS HMAC-SHA256 fallback (FIPS 180-4 SHA-256 + RFC 2104 HMAC)
// ───────────────────────────────────────────────────────────────────────────
//
// Web Crypto's `crypto.subtle` is only exposed in a secure context (HTTPS or localhost). A
// dashboard reached over plain HTTP on a LAN address therefore cannot use it at all. Rather than
// silently dropping to unsigned requests — or pulling in a CDN dependency, which AGENT.MD forbids
// outright — this is a self-contained implementation used only when `crypto.subtle` is absent.
//
// It is deliberately written against the specification's own structure so it can be checked line
// by line, and `PureCrypto.selfTest()` verifies it against an RFC 4231 vector before it is ever
// trusted with a real request.
const PureCrypto = (() => {
    // First 32 bits of the fractional parts of the cube roots of the first 64 primes.
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // First 32 bits of the fractional parts of the square roots of the first 8 primes.
    const H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // `>>> 0` after every arithmetic step: JS numbers are doubles, and without it intermediate
    // sums exceed 2^32 and lose the wrap-around the algorithm depends on.
    const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

    // SHA-256 over a byte array, returning 32 bytes.
    function sha256(bytes) {
        const length = bytes.length;
        // Padding: 0x80, then zeros, then the 64-bit big-endian bit length.
        const withPadding = new Uint8Array((((length + 8) >> 6) + 1) << 6);
        withPadding.set(bytes);
        withPadding[length] = 0x80;

        // Bit length as a 64-bit big-endian value. The high word is computed by division rather
        // than a shift, because `<<` in JS is 32-bit and would silently truncate.
        const bitLength = length * 8;
        const view = new DataView(withPadding.buffer);
        view.setUint32(withPadding.length - 8, Math.floor(bitLength / 0x100000000), false);
        view.setUint32(withPadding.length - 4, bitLength >>> 0, false);

        const h = H0.slice();
        const w = new Uint32Array(64);

        for (let offset = 0; offset < withPadding.length; offset += 64) {
            for (let i = 0; i < 16; i++) {
                w[i] = view.getUint32(offset + i * 4, false);
            }
            for (let i = 16; i < 64; i++) {
                const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
                const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
            }

            let [a, b, c, d, e, f, g, hh] = h;

            for (let i = 0; i < 64; i++) {
                const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
                const ch = ((e & f) ^ (~e & g)) >>> 0;
                const temp1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
                const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
                const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                const temp2 = (S0 + maj) >>> 0;

                hh = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            h[0] = (h[0] + a) >>> 0;
            h[1] = (h[1] + b) >>> 0;
            h[2] = (h[2] + c) >>> 0;
            h[3] = (h[3] + d) >>> 0;
            h[4] = (h[4] + e) >>> 0;
            h[5] = (h[5] + f) >>> 0;
            h[6] = (h[6] + g) >>> 0;
            h[7] = (h[7] + hh) >>> 0;
        }

        const out = new Uint8Array(32);
        const outView = new DataView(out.buffer);
        h.forEach((word, i) => outView.setUint32(i * 4, word, false));
        return out;
    }

    // RFC 2104 HMAC-SHA256. Block size is 64 bytes; a key longer than that is hashed first, and a
    // shorter one is zero-padded.
    function hmacSha256(keyBytes, messageBytes) {
        const BLOCK = 64;
        let key = keyBytes;
        if (key.length > BLOCK) key = sha256(key);

        const padded = new Uint8Array(BLOCK);
        padded.set(key);

        const inner = new Uint8Array(BLOCK + messageBytes.length);
        const outer = new Uint8Array(BLOCK + 32);
        for (let i = 0; i < BLOCK; i++) {
            inner[i] = padded[i] ^ 0x36;
            outer[i] = padded[i] ^ 0x5c;
        }
        inner.set(messageBytes, BLOCK);
        outer.set(sha256(inner), BLOCK);

        return sha256(outer);
    }

    const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

    // RFC 4231 test case 2 ("Jefe" / "what do ya want for nothing?"). Chosen because its key is
    // shorter than the block size and its message spans a padding boundary, so a mistake in either
    // the padding or the ipad/opad construction shows up here.
    function selfTest() {
        const enc = new TextEncoder();
        const digest = toHex(hmacSha256(enc.encode('Jefe'), enc.encode('what do ya want for nothing?')));
        return digest === '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';
    }

    return { sha256, hmacSha256, toHex, selfTest };
})();

// Signs a request the way the backend expects: HMAC-SHA256 over the canonical string
//
//     METHOD \n PATH_AND_QUERY \n TIMESTAMP \n RAW_BODY
//
// The newline delimiters, the query string, and the exact raw body all matter — see
// `signature_base` in src/middleware.rs for why each component is covered.
//
// Web Crypto only exposes `crypto.subtle` in a secure context (HTTPS, or localhost). A dashboard
// served over plain HTTP on a LAN address therefore *cannot* sign, so callers must treat a null
// return as "signing unavailable" and fall back to bearer-only auth rather than sending a
// half-formed signature.
class RequestSigner {
    constructor(signingSecret, hmacMode = 'CANONICAL_V1') {
        this.signingSecret = signingSecret || '';
        this.hmacMode = hmacMode;
        this.cryptoKey = null;
        // Memoized once: 'subtle' | 'pure' | 'none'.
        this._backend = null;
    }

    // Which implementation will actually be used. `crypto.subtle` is preferred wherever it exists
    // (native, constant-time, non-extractable key); the pure-JS path is the plain-HTTP fallback and
    // is only trusted after it reproduces a known RFC 4231 digest — a subtly broken hash would
    // otherwise show up as an inexplicable stream of 401s.
    get backend() {
        if (this._backend === null) {
            if (!this.signingSecret) {
                this._backend = 'none';
            } else if (globalThis.crypto?.subtle) {
                this._backend = 'subtle';
            } else if (PureCrypto.selfTest()) {
                console.info(
                    'Web Crypto is unavailable (insecure context); using the built-in pure-JS ' +
                    'HMAC-SHA256 implementation, which passed its RFC 4231 self-test.'
                );
                this._backend = 'pure';
            } else {
                console.error('Pure-JS HMAC self-test FAILED; refusing to sign with it.');
                this._backend = 'none';
            }
        }
        return this._backend;
    }

    get available() {
        return this.backend !== 'none';
    }

    // Imports the secret once and caches the non-extractable CryptoKey.
    async key() {
        if (!this.cryptoKey) {
            this.cryptoKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(this.signingSecret),
                { name: 'HMAC', hash: 'SHA-256' },
                false, // non-extractable: the imported key cannot be read back out
                ['sign']
            );
        }
        return this.cryptoKey;
    }

    // Hex HMAC-SHA256 of `message` under the signing secret, via whichever backend is active.
    async digest(message) {
        const enc = new TextEncoder();
        if (this.backend === 'subtle') {
            const signature = await crypto.subtle.sign('HMAC', await this.key(), enc.encode(message));
            return [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');
        }
        return PureCrypto.toHex(
            PureCrypto.hmacSha256(enc.encode(this.signingSecret), enc.encode(message))
        );
    }

    // Returns the signature headers for a request, or null when signing is unavailable.
    //
    // The signed material depends on the key's own `hmac_mode`, mirroring the backend exactly:
    // CANONICAL_V1 signs METHOD/PATH/TIMESTAMP/BODY and sends X-Timestamp; BODY_ONLY signs the raw
    // body alone and sends no timestamp, because none would be covered by that signature.
    async headers(method, pathAndQuery, body) {
        if (!this.available) return null;

        const payload = body ?? '';
        try {
            if (this.hmacMode === 'BODY_ONLY') {
                return { 'X-Signature-256': `sha256=${await this.digest(payload)}` };
            }
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const canonical = `${method.toUpperCase()}\n${pathAndQuery}\n${timestamp}\n${payload}`;
            return {
                'X-Timestamp': timestamp,
                'X-Signature-256': `sha256=${await this.digest(canonical)}`
            };
        } catch (e) {
            // Never fall through to an unsigned request silently under a wrong assumption; the
            // caller decides, and the console records why.
            console.error('Request signing failed:', e);
            return null;
        }
    }
}

class HookExecutorClient {
    constructor() {
        this.apiKey = localStorage.getItem('simply_hook_executor_key') || '';
        this.signer = new RequestSigner(localStorage.getItem('simply_hook_executor_signing_secret') || '');
        this.apiBase = '/api';
        this.state = {
            profile: null,
            hooks: [],
            apiKeys: [],
            settings: null,
            // Row-selection state for the batch-delete checkboxes, keyed by each row's own
            // stable UUID.
            selectedExecutionIds: new Set(),
            selectedHookIds: new Set(),
            selectedKeyIds: new Set()
        };

        // Executions and audit logs are both large, append-only lists — fetched 100 at a time and
        // paginated locally 15 at a time, instead of one network round-trip per page.
        this.execCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchExecutionsChunk(offset, limit) });
        this.auditCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchAuditLogsChunk(offset, limit) });

        this.runHookCombobox = new SearchableSelect({
            rootId: 'run-hook-combobox',
            searchId: 'run-hook-search',
            valueId: 'run-hook-id',
            emptyText: 'No matching hooks',
            onSelect: (hookId) => this.onRunHookSelected(hookId)
        });
        this.execHookFilterCombobox = new SearchableSelect({
            rootId: 'exec-hook-filter-combobox',
            searchId: 'exec-hook-filter',
            valueId: 'exec-hook-filter',
            allowFreeText: true,
            emptyText: 'No matching hooks',
            onSelect: () => this.loadExecutions()
        });
        this.rightsHookCombobox = new SearchableSelect({
            rootId: 'manage-rights-hook-combobox',
            searchId: 'manage-rights-hook-search',
            valueId: 'manage-rights-hook',
            emptyText: 'No matching hooks'
        });

        this.init();
    }

    async init() {
        this.bindEvents();
        if (this.apiKey) {
            await this.verifyAuth();
        } else {
            this.showLogin();
        }
    }

    // ───────────────────────────────────────────────────────
    // Fetch Wrapper (Global 401 interceptor)
    // ───────────────────────────────────────────────────────
    async apiFetch(endpoint, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        // The signature covers the path the server actually receives, including the /api prefix
        // and any query string — so it must be built from the full request target, not `endpoint`.
        const pathAndQuery = `${this.apiBase}${endpoint}`;
        // `body` is signed byte-for-byte as sent; an absent body signs as the empty string, which
        // is what the backend uses for GET/DELETE without a payload.
        const body = options.body ?? '';

        const signatureHeaders = await this.signer.headers(method, pathAndQuery, body);

        const headers = {
            'Content-Type': 'application/json',
            ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
            ...(signatureHeaders || {}),
            ...(options.headers || {})
        };

        try {
            const res = await fetch(pathAndQuery, { ...options, headers });

            // 401 means the key itself is invalid/missing — the session is unrecoverable, so log
            // out. 403 means the key IS valid but lacks permission for this one action; it must
            // NOT log the user out or swallow the server's specific "Permission denied: ..."
            // message, which is exactly what the user needs to see.
            if (res.status === 401) {
                this.handleAuthFailure();
                throw new Error("Session expired or invalid API key — please log in again.");
            }

            // Read the body as text first and only parse when there's something to parse: several
            // endpoints return a bare 200 or a 204 with no body at all, and `res.json()` throws
            // "Unexpected end of JSON input" on either.
            const text = await res.text();
            let data = {};
            if (text && text.trim().length > 0) {
                try {
                    data = JSON.parse(text);
                } catch {
                    data = text;
                }
            }

            if (!res.ok) {
                const errMsg = (data && typeof data === 'object' ? data.error : null)
                    || (typeof data === 'string' ? data : null)
                    || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }

            return data;

        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }

    // ───────────────────────────────────────────────────────
    // Auth Flow
    // ───────────────────────────────────────────────────────
    handleAuthFailure() {
        this.apiKey = '';
        this.signer = new RequestSigner('');
        localStorage.removeItem('simply_hook_executor_key');
        // Cleared alongside the key: leaving a signing secret behind after logout would keep a
        // forgeable credential in the browser for the next person at that machine.
        localStorage.removeItem('simply_hook_executor_signing_secret');
        this.showLogin();
    }

    async verifyAuth() {
        try {
            this.state.profile = await this.apiFetch('/auth/me');
            // The server is authoritative about how this key's signatures are verified, so adopt
            // its mode rather than assuming CANONICAL_V1. A BODY_ONLY key signs the body alone.
            if (this.state.profile.hmac_mode && this.state.profile.hmac_mode !== this.signer.hmacMode) {
                this.signer = new RequestSigner(this.signer.signingSecret, this.state.profile.hmac_mode);
            }
            this.showDashboard();
            this.enforceRBACUI();
            this.loadInitialData();
        } catch (e) {
            // Interceptor handles logout
        }
    }

    async login(key, signingSecret) {
        this.apiKey = key;
        localStorage.setItem('simply_hook_executor_key', key);

        this.signer = new RequestSigner(signingSecret);
        if (signingSecret) {
            localStorage.setItem('simply_hook_executor_signing_secret', signingSecret);
            if (!this.signer.available) {
                // Both backends are out: no secure context *and* the pure-JS fallback failed its
                // self-test. Say so plainly instead of letting every request quietly go unsigned.
                this.showToast(
                    'Signing unavailable: no Web Crypto and the built-in fallback failed its self-test. Requests will use the API key only.',
                    'error'
                );
            }
        } else {
            localStorage.removeItem('simply_hook_executor_signing_secret');
        }

        document.getElementById('login-error').classList.add('hidden');
        await this.verifyAuth();
    }

    logout() {
        this.handleAuthFailure();
        this.showToast("Logged out successfully", 'success');
    }

    enforceRBACUI() {
        const p = this.state.profile;
        const canManageAnyHook = p.is_master
            || p.can_manage_hooks
            || (p.hook_permissions || []).some(h => h.can_manage);

        document.getElementById('identity-badge').textContent =
            `${p.name} (${p.prefix}...)${p.is_master ? ' · Master' : ''}`;

        // Hooks Management: anyone who can create hooks, or manage at least one existing hook.
        document.getElementById('hooks-tab-btn').style.display = canManageAnyHook ? 'inline-block' : 'none';
        // The create form specifically needs the global creation scope.
        document.getElementById('form-create-hook').style.display =
            (p.is_master || p.can_manage_hooks) ? 'block' : 'none';

        document.getElementById('keys-tab-btn').style.display =
            (p.is_master || p.can_manage_keys) ? 'inline-block' : 'none';

        // Settings and audit logs are master-only on the backend, so hide the tab entirely
        // rather than show it and let every request 403.
        document.getElementById('settings-tab-btn').style.display = p.is_master ? 'inline-block' : 'none';

        // A key with no executable hook has nothing to run.
        const canExecuteAny = p.is_master || (p.hook_permissions || []).some(h => h.can_execute);
        document.getElementById('run-hook-section').style.display = canExecuteAny ? 'block' : 'none';

        // Assigning run_as_user is a privilege-escalation request and is master-only server side.
        // The field is disabled rather than merely hidden, so a non-master sees that the capability
        // exists and why it is unavailable, instead of wondering where it went.
        this.applyRunAsUserGuard();
    }

    // Disables the run_as_user inputs for non-master keys, matching the backend's 403.
    applyRunAsUserGuard() {
        const isMaster = Boolean(this.state.profile?.is_master);
        ['hook-run-as-user', 'edit-hook-run-as-user'].forEach(id => {
            const input = document.getElementById(id);
            if (!input) return;
            input.disabled = !isMaster;
            input.placeholder = isMaster
                ? 'leave empty to run as the daemon user'
                : 'master keys only';
            input.title = isMaster ? '' : 'Only master API keys can assign run_as_user privileges';
            const hint = input.nextElementSibling;
            if (hint && hint.classList.contains('text-muted')) {
                hint.textContent = isMaster
                    ? 'Runs the script via sudo -n -u <user> --. Requires a matching NOPASSWD rule in sudoers.'
                    : 'Only master API keys can assign run_as_user privileges.';
            }
        });
    }

    // ───────────────────────────────────────────────────────
    // Data Loading
    // ───────────────────────────────────────────────────────
    async loadInitialData() {
        await this.loadHooks();
        await this.loadExecutions();
        if (this.state.profile.is_master || this.state.profile.can_manage_keys) {
            await this.loadKeys();
        }
        if (this.state.profile.is_master) {
            await this.loadSettings();
            await this.loadAuditLogs();
        }
    }

    async loadHooks() {
        try {
            this.state.selectedHookIds.clear();
            this.state.hooks = await this.apiFetch('/hooks');
            this.renderHooksTable();

            const byId = this.state.hooks.map(h => ({ value: h.id, label: h.name }));
            const byName = this.state.hooks.map(h => ({ value: h.name, label: h.name }));
            this.runHookCombobox.setOptions(this.state.hooks.filter(h => h.can_execute).map(h => ({ value: h.id, label: h.name })));
            this.execHookFilterCombobox.setOptions(byName);
            this.rightsHookCombobox.setOptions(byId);
        } catch (e) {}
    }

    async fetchExecutionsChunk(offset, limit) {
        const hookQ = document.getElementById('exec-hook-filter').value;
        const statusQ = document.getElementById('exec-status-filter').value;

        const params = new URLSearchParams({ limit, offset });
        if (hookQ) params.append('hook', hookQ);
        if (statusQ) params.append('status', statusQ);

        return await this.apiFetch(`/executions?${params.toString()}`);
    }

    async loadExecutions() {
        try {
            this.state.selectedExecutionIds.clear();
            await this.execCache.loadFirstChunk();
            this.renderExecutionsTable();
            this.renderStats();
            this.updateExecPaginationUI();
        } catch (e) {}
    }

    async loadKeys() {
        try {
            this.state.selectedKeyIds.clear();
            this.state.apiKeys = await this.apiFetch('/keys');
            this.renderKeysTable();
            this.updateRightsSelector();
        } catch (e) {}
    }

    async loadSettings() {
        try {
            this.state.settings = await this.apiFetch('/settings');
            this.renderSettings();
        } catch (e) {}
    }

    async fetchAuditLogsChunk(offset, limit) {
        const params = new URLSearchParams({ limit, offset });
        return await this.apiFetch(`/audit-logs?${params.toString()}`);
    }

    async loadAuditLogs() {
        if (!this.state.profile?.is_master) return;
        try {
            await this.auditCache.loadFirstChunk();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        } catch (e) {}
    }

    // ───────────────────────────────────────────────────────
    // UI Primitives
    // ───────────────────────────────────────────────────────
    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('dashboard-container').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('dashboard-container').classList.remove('hidden');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        container.appendChild(toast);

        // The base .toast class starts hidden (opacity: 0, slid off-screen) so this class add
        // triggers the CSS transition into view. Applying it in the same tick as appendChild()
        // often gets coalesced with no visible transition, so defer one frame.
        requestAnimationFrame(() => toast.classList.add('visible'));

        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // Custom dark-themed replacement for window.confirm(). Every call re-binds its own listeners
    // and tears them down on resolve, so concurrent calls never leak or stack duplicate handlers
    // on the shared modal element.
    showConfirmModal({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-modal-title');
        const messageEl = document.getElementById('confirm-modal-message');
        const confirmBtn = document.getElementById('confirm-modal-confirm');
        const cancelBtn = document.getElementById('confirm-modal-cancel');

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = confirmText;
        cancelBtn.textContent = cancelText;
        confirmBtn.className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;

        modal.classList.remove('hidden');

        return new Promise((resolve) => {
            const cleanup = (result) => {
                modal.classList.add('hidden');
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                modal.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onKeydown);
                resolve(result);
            };
            const onConfirm = () => cleanup(true);
            const onCancel = () => cleanup(false);
            const onBackdropClick = (e) => { if (e.target === modal) cleanup(false); };
            const onKeydown = (e) => {
                if (e.key === 'Escape') cleanup(false);
                if (e.key === 'Enter') cleanup(true);
            };

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            modal.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeydown);
            confirmBtn.focus();
        });
    }

    // Wires a table's "select all" header checkbox and its .row-select body checkboxes to a
    // shared Set of selected row ids, keeping the header checkbox's state and the "Delete
    // Selected" button's enabled state + label in sync. Row checkboxes are recreated on every
    // render (tbody.innerHTML replace) so they get fresh listeners each call; the header checkbox
    // and delete button are static, so their handlers are assigned via .onchange/.onclick rather
    // than addEventListener to avoid stacking duplicates across renders.
    wireRowSelection({ tbodySelector, selectAllId, deleteBtnId, deleteBtnLabel, selectedSet, onDeleteSelected }) {
        const selectAllEl = document.getElementById(selectAllId);
        const deleteBtn = document.getElementById(deleteBtnId);
        const rowCheckboxes = () => [...document.querySelectorAll(`${tbodySelector} .row-select`)];

        const updateControls = () => {
            const boxes = rowCheckboxes();
            const checkedCount = boxes.filter(cb => cb.checked).length;
            selectAllEl.checked = boxes.length > 0 && checkedCount === boxes.length;
            selectAllEl.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
            deleteBtn.disabled = selectedSet.size === 0;
            deleteBtn.textContent = selectedSet.size > 0 ? `${deleteBtnLabel} (${selectedSet.size})` : deleteBtnLabel;
        };

        rowCheckboxes().forEach(cb => {
            cb.checked = selectedSet.has(cb.dataset.id);
            cb.addEventListener('change', () => {
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
                updateControls();
            });
        });

        selectAllEl.onchange = () => {
            rowCheckboxes().forEach(cb => {
                cb.checked = selectAllEl.checked;
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
            });
            updateControls();
        };

        deleteBtn.onclick = () => onDeleteSelected();

        updateControls();
    }

    // ───────────────────────────────────────────────────────
    // Rendering — Executions / Dashboard
    // ───────────────────────────────────────────────────────
    statusBadge(status) {
        const cls = { SUCCESS: 'badge-success', FAILED: 'badge-failed', TIMEOUT: 'badge-timeout' }[status] || 'badge-scope';
        return `<span class="badge ${cls}">${escapeHtml(status)}</span>`;
    }

    renderStats() {
        // Computed over the whole cached chunk (up to 100 records), not just the visible page, so
        // the tiles summarize the current filter rather than the current scroll position.
        const items = this.execCache.items;
        const count = (s) => items.filter(e => e.status === s).length;
        const durations = items.map(e => e.duration_ms).filter(d => typeof d === 'number');
        const avg = durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : null;

        document.getElementById('stat-total').textContent = items.length;
        document.getElementById('stat-success').textContent = count('SUCCESS');
        document.getElementById('stat-failed').textContent = count('FAILED');
        document.getElementById('stat-timeout').textContent = count('TIMEOUT');
        document.getElementById('stat-duration').textContent = avg === null ? '–' : formatDuration(avg);
    }

    renderExecutionsTable() {
        const tbody = document.getElementById('executions-table-body');
        const rows = this.execCache.currentPageItems;

        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No executions recorded.</td></tr>';
        } else {
            tbody.innerHTML = rows.map(e => `
                <tr>
                    <td><input type="checkbox" class="row-select" data-id="${e.id}"></td>
                    <td class="text-sm">${new Date(e.timestamp + 'Z').toLocaleString()}</td>
                    <td><strong>${escapeHtml(e.hook_name)}</strong></td>
                    <td>${this.statusBadge(e.status)}</td>
                    <td class="font-mono text-sm">${e.exit_code === null || e.exit_code === undefined ? '–' : e.exit_code}</td>
                    <td class="text-sm">${formatDuration(e.duration_ms)}</td>
                    <td>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openExecutionModal('${e.id}')">View</button>
                            <button class="btn btn-sm btn-danger" onclick="window.app.deleteExecution('${e.id}')">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        this.wireRowSelection({
            tbodySelector: '#executions-table-body', selectAllId: 'select-all-executions',
            deleteBtnId: 'delete-selected-executions', deleteBtnLabel: 'Delete Selected',
            selectedSet: this.state.selectedExecutionIds,
            onDeleteSelected: () => this.batchDeleteExecutions()
        });
    }

    updateExecPaginationUI() {
        document.getElementById('exec-btn-prev').disabled = !this.execCache.hasPrevPage;
        document.getElementById('exec-btn-next').disabled = !this.execCache.hasNextPage;
        document.getElementById('exec-page-indicator').textContent = `Page ${this.execCache.localPage + 1}`;
    }

    // ───────────────────────────────────────────────────────
    // Rendering — Run a Hook
    // ───────────────────────────────────────────────────────
    onRunHookSelected(hookId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        const meta = document.getElementById('run-hook-meta');
        const params = document.getElementById('run-hook-params');
        const result = document.getElementById('run-hook-result');
        result.classList.add('hidden');

        if (!hook) {
            meta.classList.add('hidden');
            params.innerHTML = '<p class="text-muted text-sm">Select a hook to see its parameters.</p>';
            document.getElementById('btn-execute-hook').disabled = true;
            document.getElementById('btn-test-hook').disabled = true;
            return;
        }

        meta.classList.remove('hidden');
        meta.innerHTML = `
            <div class="font-mono text-sm">${escapeHtml(hook.script_path)}</div>
            <div class="text-muted text-sm">Timeout: ${hook.default_timeout_seconds}s${hook.description ? ' · ' + escapeHtml(hook.description) : ''}</div>
            ${hook.run_as_user ? `<div class="mt-2">${this.privilegeBadge(hook.run_as_user)}</div>` : ''}
        `;

        if (hook.parameters.length === 0) {
            params.innerHTML = '<p class="text-muted text-sm">This hook takes no parameters.</p>';
        } else {
            params.innerHTML = hook.parameters.map(p => `
                <div class="form-group">
                    <label for="param-field-${p.id}">
                        ${escapeHtml(p.param_key)}${p.is_required && p.default_value === null ? ' <span>*</span>' : ''}
                    </label>
                    <input type="text" id="param-field-${p.id}" class="input-field param-input" data-key="${escapeHtml(p.param_key)}"
                        placeholder="${p.default_value !== null ? 'default: ' + escapeHtml(p.default_value) : (p.is_required ? 'required' : 'optional')}">
                    ${p.description ? `<span class="text-muted text-sm">${escapeHtml(p.description)}</span>` : ''}
                </div>
            `).join('');
        }

        document.getElementById('btn-execute-hook').disabled = false;
        document.getElementById('btn-test-hook').disabled = false;
    }

    // Collects the run form's parameter inputs. Blank fields are omitted rather than sent as an
    // empty string, so the hook's declared default_value still applies.
    collectRunParameters() {
        const parameters = {};
        document.querySelectorAll('#run-hook-params .param-input').forEach(input => {
            const value = input.value;
            if (value !== '') parameters[input.dataset.key] = value;
        });
        return parameters;
    }

    outputBlock(label, content) {
        const body = content && content.length > 0 ? escapeHtml(content) : '<span class="text-muted">(empty)</span>';
        return `<div class="output-group"><span class="output-label">${escapeHtml(label)}</span><pre class="output-block">${body}</pre></div>`;
    }

    async executeHook(e) {
        e.preventDefault();
        const hookId = document.getElementById('run-hook-id').value;
        if (!hookId) {
            this.showToast('Select a hook first', 'error');
            return;
        }

        const btn = document.getElementById('btn-execute-hook');
        btn.disabled = true;
        btn.textContent = 'Executing...';
        try {
            const res = await this.apiFetch(`/hooks/${hookId}/execute`, {
                method: 'POST',
                body: JSON.stringify({ parameters: this.collectRunParameters() })
            });

            const panel = document.getElementById('run-hook-result');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <div class="result-header">
                    ${this.statusBadge(res.status)}
                    <span class="text-sm text-muted">exit ${res.exit_code === null ? '–' : res.exit_code} · ${formatDuration(res.duration_ms)}</span>
                </div>
                ${this.outputBlock('stdout', res.stdout)}
                ${this.outputBlock('stderr', res.stderr)}
            `;
            this.showToast(`Execution finished: ${res.status}`, res.status === 'SUCCESS' ? 'success' : 'error');
            this.loadExecutions();
        } catch (err) {
        } finally {
            btn.disabled = false;
            btn.textContent = 'Execute';
        }
    }

    async testHook() {
        const hookId = document.getElementById('run-hook-id').value;
        if (!hookId) {
            this.showToast('Select a hook first', 'error');
            return;
        }

        try {
            const res = await this.apiFetch(`/hooks/${hookId}/test`, {
                method: 'POST',
                body: JSON.stringify({ parameters: this.collectRunParameters() })
            });

            const envRows = Object.entries(res.command.env)
                .map(([k, v]) => `${k}=${v}`).join('\n');
            const argList = res.command.args.length
                ? res.command.args.map((a, i) => `argv[${i + 1}] = ${a}`).join('\n')
                : '(none)';

            const panel = document.getElementById('run-hook-result');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <div class="result-header">
                    <span class="badge ${res.would_execute ? 'badge-success' : 'badge-failed'}">
                        ${res.would_execute ? 'DRY RUN OK' : 'BLOCKED'}
                    </span>
                    <span class="text-sm text-muted">timeout ${res.timeout_seconds}s</span>
                    ${res.command.run_as_user ? this.privilegeBadge(res.command.run_as_user) : ''}
                </div>
                ${res.blocking_reason ? `<p class="message error">${escapeHtml(res.blocking_reason)}</p>` : ''}
                ${this.outputBlock('command', res.command.program)}
                ${this.outputBlock('positional arguments', argList)}
                ${this.outputBlock('environment', envRows)}
            `;
            this.showToast(res.would_execute ? 'Dry run resolved successfully' : 'Dry run blocked', res.would_execute ? 'success' : 'error');
        } catch (err) {}
    }

    async openExecutionModal(id) {
        try {
            const e = await this.apiFetch(`/executions/${id}`);
            const paramRows = Object.entries(e.parameters || {}).length
                ? Object.entries(e.parameters).map(([k, v]) => `${k} = ${v}`).join('\n')
                : '(none)';

            document.getElementById('execution-modal-body').innerHTML = `
                <div class="kv-grid">
                    <div class="kv-item"><span class="kv-key">Hook</span><span class="kv-value">${escapeHtml(e.hook_name)}</span></div>
                    <div class="kv-item"><span class="kv-key">Status</span><span class="kv-value">${this.statusBadge(e.status)}</span></div>
                    <div class="kv-item"><span class="kv-key">Exit code</span><span class="kv-value font-mono">${e.exit_code === null ? '–' : e.exit_code}</span></div>
                    <div class="kv-item"><span class="kv-key">Duration</span><span class="kv-value">${formatDuration(e.duration_ms)}</span></div>
                    <div class="kv-item"><span class="kv-key">Started</span><span class="kv-value">${new Date(e.timestamp + 'Z').toLocaleString()}</span></div>
                    <div class="kv-item"><span class="kv-key">Execution ID</span><span class="kv-value font-mono text-sm">${escapeHtml(e.id)}</span></div>
                </div>
                ${this.outputBlock('parameters', paramRows)}
                ${this.outputBlock('stdout', e.stdout)}
                ${this.outputBlock('stderr', e.stderr)}
            `;
            document.getElementById('execution-modal').classList.remove('hidden');
        } catch (err) {}
    }

    async deleteExecution(id) {
        const ok = await this.showConfirmModal({
            title: 'Delete Execution',
            message: 'Delete this execution record and its captured output?',
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/executions/${id}`, { method: 'DELETE' });
            this.showToast('Execution deleted', 'success');
            this.loadExecutions();
        } catch (e) {}
    }

    async batchDeleteExecutions() {
        const ids = [...this.state.selectedExecutionIds];
        if (ids.length === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected Executions',
            message: `Delete ${ids.length} selected execution record${ids.length === 1 ? '' : 's'}? This cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/executions/${id}`, { method: 'DELETE' })));
        this.reportBatchResult(results, ids.length, 'execution');
        this.loadExecutions();
    }

    reportBatchResult(results, count, noun) {
        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0
                ? `${count} ${noun}${count === 1 ? '' : 's'} deleted`
                : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
    }

    // ───────────────────────────────────────────────────────
    // Rendering — Hooks
    // ───────────────────────────────────────────────────────

    // A hook that escalates via sudo is the highest-consequence thing in this UI, so it gets a
    // loud, distinctly-coloured tag naming the target account rather than a subtle marker.
    privilegeBadge(runAsUser) {
        if (!runAsUser) return '<span class="text-muted text-sm">daemon user</span>';
        return `<span class="badge badge-elevated" title="Runs via sudo -n -u ${escapeHtml(runAsUser)} --">⬆ ${escapeHtml(runAsUser)}</span>`;
    }

    // Collects a hook's parameters for a table-initiated run. Only parameters that already carry
    // a default can be resolved without a form, so a hook with unsatisfied required parameters is
    // routed to the Run panel rather than being launched with a guess.
    hookNeedsInput(hook) {
        return hook.parameters.some(p => p.is_required && p.default_value === null);
    }

    sendToRunPanel(hook, message) {
        this.showToast(message, 'info');
        document.querySelector('.tab-btn[data-tab="executions"]').click();
        this.runHookCombobox.select({ value: hook.id, label: hook.name });
    }

    // Test = dry run. It resolves parameters and renders the exact command, environment and
    // timeout that *would* be used, and deliberately spawns nothing — so there is no stdout,
    // stderr or exit code to show, and claiming otherwise would be a lie about what ran.
    async testHookFromTable(hookId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        if (!hook) return;
        if (this.hookNeedsInput(hook)) {
            this.sendToRunPanel(hook, 'This hook has required parameters — fill them in below, then Dry Run.');
            return;
        }

        try {
            const res = await this.apiFetch(`/hooks/${hookId}/test`, {
                method: 'POST',
                body: JSON.stringify({ parameters: {} })
            });

            const envRows = Object.entries(res.command.env).map(([k, v]) => `${k}=${v}`).join('\n');
            const argList = res.command.args.length
                ? res.command.args.map((a, i) => `argv[${i + 1}] = ${a}`).join('\n')
                : '(none)';

            this.showHookResultModal(`Dry Run — ${hook.name}`, `
                <div class="result-header">
                    <span class="badge ${res.would_execute ? 'badge-success' : 'badge-failed'}">
                        ${res.would_execute ? 'WOULD EXECUTE' : 'BLOCKED'}
                    </span>
                    <span class="text-sm text-muted">timeout ${res.timeout_seconds}s</span>
                    ${res.command.run_as_user ? this.privilegeBadge(res.command.run_as_user) : ''}
                </div>
                <p class="subtitle">Nothing was executed — this is the command that would run.</p>
                ${res.blocking_reason ? `<p class="message error">${escapeHtml(res.blocking_reason)}</p>` : ''}
                ${this.outputBlock('program', res.command.program)}
                ${this.outputBlock('positional arguments', argList)}
                ${this.outputBlock('environment', envRows)}
            `);
        } catch (e) {}
    }

    // Launch = the real thing, with the recorded stdout/stderr/exit code.
    async launchHookFromTable(hookId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        if (!hook) return;
        if (this.hookNeedsInput(hook)) {
            this.sendToRunPanel(hook, 'This hook has required parameters — fill them in below, then Execute.');
            return;
        }

        const ok = await this.showConfirmModal({
            title: `Launch "${hook.name}"`,
            message: hook.run_as_user
                ? `This runs ${hook.script_path} as "${hook.run_as_user}" via sudo. Continue?`
                : `This runs ${hook.script_path} for real. Continue?`,
            confirmText: 'Launch',
            danger: Boolean(hook.run_as_user)
        });
        if (!ok) return;

        try {
            const res = await this.apiFetch(`/hooks/${hookId}/execute`, {
                method: 'POST',
                body: JSON.stringify({ parameters: {} })
            });

            this.showHookResultModal(`Execution — ${hook.name}`, `
                <div class="result-header">
                    ${this.statusBadge(res.status)}
                    <span class="text-sm text-muted">exit ${res.exit_code === null ? '–' : res.exit_code} · ${formatDuration(res.duration_ms)}</span>
                    ${hook.run_as_user ? this.privilegeBadge(hook.run_as_user) : ''}
                </div>
                ${this.outputBlock('stdout', res.stdout)}
                ${this.outputBlock('stderr', res.stderr)}
            `);
            this.showToast(`Execution finished: ${res.status}`, res.status === 'SUCCESS' ? 'success' : 'error');
            this.loadExecutions();
        } catch (e) {}
    }

    // Jumps to the execution history filtered to this hook.
    showHookLogs(hookId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        if (!hook) return;
        document.querySelector('.tab-btn[data-tab="executions"]').click();
        document.getElementById('exec-hook-filter').value = hook.name;
        this.loadExecutions();
    }

    showHookResultModal(title, bodyHtml) {
        document.getElementById('hook-result-title').textContent = title;
        document.getElementById('hook-result-body').innerHTML = bodyHtml;
        document.getElementById('hook-result-modal').classList.remove('hidden');
    }

    renderHooksTable() {
        const tbody = document.getElementById('hooks-table-body');

        if (this.state.hooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No hooks defined.</td></tr>';
        } else {
            tbody.innerHTML = this.state.hooks.map(h => {
                const rights = [
                    h.can_execute ? '<span class="badge badge-scope">Execute</span>' : '',
                    h.can_manage ? '<span class="badge badge-scope">Manage</span>' : ''
                ].filter(Boolean).join('') || '<span class="text-muted text-sm">None</span>';

                return `
                <tr>
                    <td>${h.can_manage ? `<input type="checkbox" class="row-select" data-id="${h.id}">` : ''}</td>
                    <td><strong>${escapeHtml(h.name)}</strong></td>
                    <td class="font-mono text-sm truncate">${escapeHtml(h.script_path)}</td>
                    <td>${this.privilegeBadge(h.run_as_user)}</td>
                    <td class="text-sm">${h.default_timeout_seconds}s</td>
                    <td class="text-sm">${h.parameters.length}</td>
                    <td><div class="scope-badges">${rights}</div></td>
                    <td>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="window.app.testHookFromTable('${h.id}')" ${h.can_execute ? '' : 'disabled'}
                                title="${h.can_execute ? 'Dry run: resolve the command without executing it' : 'Requires execute permission'}">Test</button>
                            <button class="btn btn-sm btn-primary" onclick="window.app.launchHookFromTable('${h.id}')" ${h.can_execute ? '' : 'disabled'}
                                title="${h.can_execute ? 'Execute this hook for real' : 'Requires execute permission'}">Launch</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.showHookLogs('${h.id}')">Logs</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openParamsModal('${h.id}')" ${h.can_manage ? '' : 'disabled'}>Parameters</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openEditHookModal('${h.id}')" ${h.can_manage ? '' : 'disabled'}>Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="window.app.deleteHook('${h.id}')" ${h.can_manage ? '' : 'disabled'}>Delete</button>
                        </div>
                    </td>
                </tr>
            `;
            }).join('');
        }

        this.wireRowSelection({
            tbodySelector: '#hooks-table-body', selectAllId: 'select-all-hooks',
            deleteBtnId: 'delete-selected-hooks', deleteBtnLabel: 'Delete Selected',
            selectedSet: this.state.selectedHookIds,
            onDeleteSelected: () => this.batchDeleteHooks()
        });
    }

    async createHook(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('hook-name').value,
            script_path: document.getElementById('hook-script-path').value,
            default_timeout_seconds: parseInt(document.getElementById('hook-timeout').value, 10),
            // Blank means "no elevation"; the backend normalizes it to NULL.
            run_as_user: document.getElementById('hook-run-as-user').value.trim() || null,
            description: document.getElementById('hook-description').value || null
        };
        try {
            await this.apiFetch('/hooks', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-create-hook').reset();
            document.getElementById('hook-timeout').value = 30;
            this.showToast('Hook created', 'success');
            this.loadHooks();
        } catch (err) {}
    }

    openEditHookModal(id) {
        const h = this.state.hooks.find(h => h.id === id);
        if (!h) return;
        document.getElementById('edit-hook-id').value = h.id;
        document.getElementById('edit-hook-name').value = h.name;
        document.getElementById('edit-hook-script-path').value = h.script_path;
        document.getElementById('edit-hook-timeout').value = h.default_timeout_seconds;
        document.getElementById('edit-hook-run-as-user').value = h.run_as_user || '';
        document.getElementById('edit-hook-description').value = h.description || '';
        // Re-applied on open: the modal's inputs persist across renders, so the guard has to be
        // reasserted rather than assumed from login time.
        this.applyRunAsUserGuard();
        document.getElementById('edit-hook-modal').classList.remove('hidden');
    }

    async submitEditHook(e) {
        e.preventDefault();
        const id = document.getElementById('edit-hook-id').value;
        const payload = {
            name: document.getElementById('edit-hook-name').value,
            script_path: document.getElementById('edit-hook-script-path').value,
            default_timeout_seconds: parseInt(document.getElementById('edit-hook-timeout').value, 10),
            // Always sent, so clearing the field is an explicit "drop elevation" rather than a
            // no-op: the backend distinguishes an empty string from an absent field.
            run_as_user: document.getElementById('edit-hook-run-as-user').value.trim(),
            description: document.getElementById('edit-hook-description').value
        };
        try {
            await this.apiFetch(`/hooks/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            document.getElementById('edit-hook-modal').classList.add('hidden');
            this.showToast('Hook updated', 'success');
            this.loadHooks();
        } catch (err) {}
    }

    async deleteHook(id) {
        const hook = this.state.hooks.find(h => h.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete Hook',
            message: `Delete the hook "${hook ? hook.name : id}"? Its parameters, permissions, and execution history are removed with it.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/hooks/${id}`, { method: 'DELETE' });
            this.showToast('Hook deleted', 'success');
            this.loadHooks();
            this.loadExecutions();
        } catch (e) {}
    }

    async batchDeleteHooks() {
        const ids = [...this.state.selectedHookIds];
        if (ids.length === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected Hooks',
            message: `Delete ${ids.length} selected hook${ids.length === 1 ? '' : 's'}? Their parameters, permissions, and history are removed too.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/hooks/${id}`, { method: 'DELETE' })));
        this.reportBatchResult(results, ids.length, 'hook');
        this.loadHooks();
        this.loadExecutions();
    }

    // ───────────────────────────────────────────────────────
    // Rendering — Hook parameters modal
    // ───────────────────────────────────────────────────────
    openParamsModal(hookId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        if (!hook) return;
        document.getElementById('params-modal-hook-id').value = hookId;
        document.getElementById('params-modal-title').textContent = `Parameters — ${hook.name}`;
        this.renderParamsTable(hook);
        document.getElementById('params-modal').classList.remove('hidden');
    }

    renderParamsTable(hook) {
        const tbody = document.getElementById('params-table-body');
        if (hook.parameters.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No parameters declared.</td></tr>';
            return;
        }
        tbody.innerHTML = hook.parameters.map((p, i) => `
            <tr>
                <td class="text-muted text-sm">${i + 1}</td>
                <td class="font-mono">${escapeHtml(p.param_key)}</td>
                <td class="font-mono text-sm">${p.default_value === null ? '<span class="text-muted">–</span>' : escapeHtml(p.default_value)}</td>
                <td>${p.is_required ? '<span class="badge badge-scope">Required</span>' : '<span class="text-muted text-sm">Optional</span>'}</td>
                <td class="text-sm">${escapeHtml(p.description || '–')}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="window.app.deleteParameter('${hook.id}', '${p.id}')">Delete</button>
                </td>
            </tr>
        `).join('');
    }

    async addParameter(e) {
        e.preventDefault();
        const hookId = document.getElementById('params-modal-hook-id').value;
        const defaultValue = document.getElementById('param-default').value;
        const payload = {
            param_key: document.getElementById('param-key').value,
            description: document.getElementById('param-description').value || null,
            default_value: defaultValue === '' ? null : defaultValue,
            is_required: document.getElementById('param-required').checked
        };
        try {
            await this.apiFetch(`/hooks/${hookId}/parameters`, { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-add-param').reset();
            document.getElementById('param-required').checked = true;
            this.showToast('Parameter added', 'success');
            await this.loadHooks();
            const hook = this.state.hooks.find(h => h.id === hookId);
            if (hook) this.renderParamsTable(hook);
        } catch (err) {}
    }

    async deleteParameter(hookId, paramId) {
        const ok = await this.showConfirmModal({
            title: 'Delete Parameter',
            message: 'Remove this parameter from the hook contract?',
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/hooks/${hookId}/parameters/${paramId}`, { method: 'DELETE' });
            this.showToast('Parameter removed', 'success');
            await this.loadHooks();
            const hook = this.state.hooks.find(h => h.id === hookId);
            if (hook) this.renderParamsTable(hook);
        } catch (e) {}
    }

    // ───────────────────────────────────────────────────────
    // Rendering — API keys
    // ───────────────────────────────────────────────────────
    renderKeysTable() {
        const tbody = document.getElementById('apikeys-table-body');
        if (this.state.apiKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No API keys.</td></tr>';
        } else {
            tbody.innerHTML = this.state.apiKeys.map(k => `
                <tr>
                    <td><input type="checkbox" class="row-select" data-id="${k.id}"></td>
                    <td><strong>${escapeHtml(k.name)}</strong><div class="text-muted text-sm font-mono">${escapeHtml(k.prefix)}...</div></td>
                    <td class="font-mono text-sm">
                        ${k.key_id ? escapeHtml(k.key_id) : '<span class="text-muted">none — rotate to mint</span>'}
                        ${k.key_id && !k.has_signing_secret ? '<div class="text-muted text-sm">no signing secret</div>' : ''}
                    </td>
                    <td>${this.hmacModeBadge(k.hmac_mode)}</td>
                    <td class="font-mono text-sm">${escapeHtml(k.bound_ips || '-')}</td>
                    <td class="text-sm">${k.max_concurrent_jobs}</td>
                    <td>${this.renderKeyScopes(k)}</td>
                    <td>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openEditKeyModal('${k.id}')">Edit</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateKeySecret('${k.id}')">Regenerate</button>
                            <button class="btn btn-sm btn-danger" onclick="window.app.deleteKey('${k.id}')">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        this.wireRowSelection({
            tbodySelector: '#apikeys-table-body', selectAllId: 'select-all-keys',
            deleteBtnId: 'delete-selected-keys', deleteBtnLabel: 'Delete Selected',
            selectedSet: this.state.selectedKeyIds,
            onDeleteSelected: () => this.batchDeleteKeys()
        });
    }

    // BODY_ONLY is visually flagged: it is the mode without replay protection, and an operator
    // scanning the key list should be able to see at a glance which keys are on it.
    hmacModeBadge(mode) {
        if (mode === 'BODY_ONLY') {
            return '<span class="badge badge-timeout" title="Body-only signatures: no replay protection">BODY_ONLY</span>';
        }
        return '<span class="badge badge-scope" title="Signs method + path + timestamp + body">CANONICAL_V1</span>';
    }

    // Global scope badges plus per-hook permission badges, each carrying a "×" to revoke that
    // specific grant.
    renderKeyScopes(k) {
        const scopes = [];
        if (k.is_master) scopes.push('<span class="badge badge-scope badge-scope-master">Master</span>');
        if (k.can_manage_keys) scopes.push('<span class="badge badge-scope">Manage Keys</span>');
        if (k.can_manage_hooks) scopes.push('<span class="badge badge-scope">Create Hooks</span>');

        const hookBadges = (k.hook_permissions || []).map(p => {
            const rights = [p.can_execute ? 'X' : '', p.can_manage ? 'M' : ''].filter(Boolean).join('') || 'none';
            return `<span class="badge badge-group" title="${escapeHtml(p.hook_name)}: ${rights}">${escapeHtml(p.hook_name)}: ${rights}
                <button type="button" class="badge-revoke" title="Revoke this hook permission" onclick="window.app.revokeHookPermission('${k.id}', '${p.hook_id}')">&times;</button>
            </span>`;
        });

        const badges = [...scopes, ...hookBadges];
        if (badges.length === 0) return '<span class="text-muted text-sm">None</span>';
        return `<div class="scope-badges">${badges.join('')}</div>`;
    }

    updateRightsSelector() {
        const sel = document.getElementById('manage-rights-key');
        if (!sel) return;
        // Master keys bypass RBAC entirely, so scoping them is meaningless (and the backend
        // rejects it with a 400).
        sel.innerHTML = '<option value="">-- Select API Key --</option>' + this.state.apiKeys
            .filter(k => !k.is_master)
            .map(k => `<option value="${k.id}">${escapeHtml(k.name)}</option>`)
            .join('');
    }

    async createApiKey(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('apikey-name').value,
            bound_ips: document.getElementById('apikey-bound-ips').value,
            max_concurrent_jobs: parseInt(document.getElementById('apikey-max-jobs').value, 10),
            hmac_mode: document.getElementById('apikey-hmac-mode').value,
            is_master: document.getElementById('apikey-is-master').checked,
            can_manage_keys: document.getElementById('apikey-can-manage-keys').checked,
            can_manage_hooks: document.getElementById('apikey-can-manage-hooks').checked
        };

        try {
            const res = await this.apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
            this.revealCredentials('API Key Created', res);
            document.getElementById('form-create-apikey').reset();
            document.getElementById('apikey-max-jobs').value = 10;
            document.getElementById('apikey-hmac-mode').value = 'CANONICAL_V1';
            this.loadKeys();
        } catch (err) {}
    }

    // One-time reveal of the credentials a key creation or rotation just minted. The signing
    // secret is stored encrypted and never returned again, so this modal is the only chance to
    // copy it — hence the deliberate friction of an "I have copied them" button.
    revealCredentials(title, res) {
        const field = (label, value, hint) => `
            <div class="form-group">
                <label>${escapeHtml(label)}</label>
                <code class="key-reveal-value">${escapeHtml(value)}</code>
                ${hint ? `<span class="text-muted text-sm">${escapeHtml(hint)}</span>` : ''}
            </div>`;

        document.getElementById('secret-reveal-title').textContent = title;
        document.getElementById('secret-reveal-body').innerHTML = [
            field('API Key', res.plaintext_key, 'Send as the X-API-Key header.'),
            field('Key ID', res.key_id, 'Public identifier. Send as X-Key-Id when authenticating by signature.'),
            field('Signing Secret', res.signing_secret, 'Secret. Compute HMAC-SHA256 over the raw JSON body and send it as X-Signature-256: sha256=<hex>.')
        ].join('');
        document.getElementById('secret-reveal-modal').classList.remove('hidden');
    }

    async manageKeyRights(e) {
        e.preventDefault();
        const keyId = document.getElementById('manage-rights-key').value;
        const hookId = document.getElementById('manage-rights-hook').value;

        if (!keyId || !hookId) {
            this.showToast('Please select both a target key and a hook', 'error');
            return;
        }

        const payload = {
            hook_id: hookId,
            can_execute: document.getElementById('manage-rights-execute').checked,
            can_manage: document.getElementById('manage-rights-manage').checked
        };

        try {
            await this.apiFetch(`/keys/${keyId}/permissions`, { method: 'POST', body: JSON.stringify(payload) });
            this.showToast('Hook rights assigned', 'success');
            document.getElementById('form-manage-rights').reset();
            document.getElementById('manage-rights-execute').checked = true;
            this.loadKeys();
        } catch (err) {}
    }

    async revokeHookPermission(keyId, hookId) {
        const ok = await this.showConfirmModal({
            title: 'Revoke Permission',
            message: "Revoke this key's permission on this hook?",
            confirmText: 'Revoke',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${keyId}/permissions/${hookId}`, { method: 'DELETE' });
            this.showToast('Permission revoked', 'success');
            this.loadKeys();
        } catch (e) {}
    }

    openEditKeyModal(id) {
        const k = this.state.apiKeys.find(k => k.id === id);
        if (!k) return;
        document.getElementById('edit-key-id').value = k.id;
        document.getElementById('edit-key-name').value = k.name;
        document.getElementById('edit-key-bound-ips').value = k.bound_ips || '';
        document.getElementById('edit-key-max-jobs').value = k.max_concurrent_jobs;
        document.getElementById('edit-key-hmac-mode').value = k.hmac_mode || 'CANONICAL_V1';
        document.getElementById('edit-key-can-manage-keys').checked = k.can_manage_keys;
        document.getElementById('edit-key-can-manage-hooks').checked = k.can_manage_hooks;
        document.getElementById('edit-key-modal').classList.remove('hidden');
    }

    async submitEditKey(e) {
        e.preventDefault();
        const id = document.getElementById('edit-key-id').value;
        const payload = {
            name: document.getElementById('edit-key-name').value,
            bound_ips: document.getElementById('edit-key-bound-ips').value,
            max_concurrent_jobs: parseInt(document.getElementById('edit-key-max-jobs').value, 10),
            hmac_mode: document.getElementById('edit-key-hmac-mode').value,
            can_manage_keys: document.getElementById('edit-key-can-manage-keys').checked,
            can_manage_hooks: document.getElementById('edit-key-can-manage-hooks').checked
        };

        try {
            await this.apiFetch(`/keys/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            this.showToast('Key updated', 'success');
            document.getElementById('edit-key-modal').classList.add('hidden');
            this.loadKeys();
        } catch (err) {}
    }

    async regenerateKeySecret(id) {
        const ok = await this.showConfirmModal({
            title: 'Regenerate Secret',
            message: "Regenerate this key's secret? The old secret stops working immediately.",
            confirmText: 'Regenerate',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/rotate`, { method: 'POST' });
            this.revealCredentials('New Credentials Generated', res);
            this.showToast('Key and signing secret rotated', 'success');
            this.loadKeys();
        } catch (e) {}
    }

    async deleteKey(id) {
        const key = this.state.apiKeys.find(k => k.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete API Key',
            message: `Delete the API key "${key ? key.name : id}"? This immediately revokes its access and cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${id}`, { method: 'DELETE' });
            this.showToast('Key deleted', 'success');
            this.loadKeys();
        } catch (e) {}
    }

    async batchDeleteKeys() {
        const ids = [...this.state.selectedKeyIds];
        if (ids.length === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected API Keys',
            message: `Delete ${ids.length} selected API key${ids.length === 1 ? '' : 's'}? This immediately revokes their access.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/keys/${id}`, { method: 'DELETE' })));
        this.reportBatchResult(results, ids.length, 'key');
        this.loadKeys();
    }

    // ───────────────────────────────────────────────────────
    // Rendering — Settings & audit
    // ───────────────────────────────────────────────────────
    renderSettings() {
        const s = this.state.settings;
        if (!s) return;
        const item = (key, value) =>
            `<div class="kv-item"><span class="kv-key">${escapeHtml(key)}</span><span class="kv-value">${value}</span></div>`;

        document.getElementById('settings-grid').innerHTML = [
            item('Passthrough env vars', s.allowed_env_vars.length
                ? `<span class="font-mono text-sm">${escapeHtml(s.allowed_env_vars.join(', '))}</span>`
                : '<span class="text-muted">(none — full isolation)</span>'),
            item('Script roots', s.allowed_script_roots.length
                ? `<span class="font-mono text-sm">${escapeHtml(s.allowed_script_roots.join(', '))}</span>`
                : '<span class="text-muted">(unrestricted — any absolute path)</span>'),
            item('Log retention', s.log_retention_days > 0 ? `${s.log_retention_days} days` : 'disabled (kept forever)'),
            item('Retention sweep', `every ${s.retention_sweep_seconds}s`),
            item('Max captured output', `${Math.round(s.max_output_bytes / 1024)} KiB per stream`),
            item('Signature window', `±${s.signature_max_age_seconds}s (anti-replay)`),
            item('Signed requests', s.require_signed_requests
                ? '<span class="badge badge-success">required</span>'
                : '<span class="text-muted">optional</span>'),
            item('Signing secrets at rest', s.signing_secrets_encrypted
                ? '<span class="badge badge-success">encrypted</span>'
                : '<span class="badge badge-timeout">unencrypted</span>'),
            item('Hooks defined', s.hook_count),
            item('API keys', s.api_key_count),
            item('Executions stored', s.execution_count)
        ].join('');
    }

    async purgeExecutions(e) {
        e.preventDefault();
        const raw = document.getElementById('purge-days').value;
        const days = raw === '' ? null : parseInt(raw, 10);
        const ok = await this.showConfirmModal({
            title: 'Purge Execution History',
            message: days === null
                ? 'Delete every execution older than the configured retention window?'
                : `Delete every execution older than ${days} day${days === 1 ? '' : 's'}?`,
            confirmText: 'Purge',
            danger: true
        });
        if (!ok) return;

        try {
            const params = days === null ? '' : `?older_than_days=${days}`;
            const res = await this.apiFetch(`/executions${params}`, { method: 'DELETE' });
            this.showToast(`Purged ${res.purged} execution record(s)`, 'success');
            this.loadSettings();
            this.loadExecutions();
        } catch (err) {}
    }

    renderAuditLogsTable() {
        const tbody = document.getElementById('audit-logs-table-body');
        const rows = this.auditCache.currentPageItems;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No audit log entries.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(log => `
            <tr>
                <td class="text-sm">${new Date(log.timestamp + 'Z').toLocaleString()}</td>
                <td class="text-sm">${escapeHtml(log.api_key_name)} <span class="text-muted text-sm">(${escapeHtml(log.api_key_prefix)}...)</span></td>
                <td class="font-mono text-sm">${escapeHtml(log.client_ip)}</td>
                <td><span class="badge badge-scope">${escapeHtml(log.action)}</span></td>
                <td class="text-sm">${escapeHtml(log.target_resource || '-')}</td>
                <td class="text-sm">${escapeHtml(log.details || '-')}</td>
            </tr>
        `).join('');
    }

    updateAuditPaginationUI() {
        document.getElementById('audit-btn-prev').disabled = !this.auditCache.hasPrevPage;
        document.getElementById('audit-btn-next').disabled = !this.auditCache.hasNextPage;
        document.getElementById('audit-page-indicator').textContent = `Page ${this.auditCache.localPage + 1}`;
    }

    // ───────────────────────────────────────────────────────
    // Event Binding
    // ───────────────────────────────────────────────────────
    bindEvents() {
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login(
                document.getElementById('login-key').value,
                document.getElementById('login-signing-secret').value.trim()
            );
        });

        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('refresh-btn').addEventListener('click', () => this.loadInitialData());

        // Tabs. Each panel is fully re-rendered from cached/fetched state on every switch rather
        // than mutated in place, so repeatedly switching tabs can never accumulate stale rows.
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-btn').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

                const trg = e.target;
                trg.classList.add('active');
                trg.setAttribute('aria-selected', 'true');
                document.getElementById(`tab-${trg.dataset.tab}`).classList.add('active');
            });
        });

        // Run a hook
        document.getElementById('run-hook-form').addEventListener('submit', (e) => this.executeHook(e));
        document.getElementById('btn-test-hook').addEventListener('click', () => this.testHook());

        // Execution filters — explicit search only: the button, Enter in the hook filter, or the
        // status dropdown's own change event. Typing alone never fires a request.
        document.getElementById('exec-search-btn').addEventListener('click', () => this.loadExecutions());
        document.getElementById('exec-status-filter').addEventListener('change', () => this.loadExecutions());
        document.getElementById('exec-hook-filter').addEventListener('keydown', (e) => {
            // If the suggestion menu is open, let its own Enter handler pick the highlighted
            // option first (which triggers a search via onSelect) — otherwise this double-fires.
            if (e.key === 'Enter' && this.execHookFilterCombobox.menu.classList.contains('hidden')) {
                e.preventDefault();
                this.loadExecutions();
            }
        });

        // Execution pagination — most clicks are a pure client-side slice of the cached chunk.
        document.getElementById('exec-btn-prev').addEventListener('click', () => {
            this.execCache.prevPage();
            this.renderExecutionsTable();
            this.updateExecPaginationUI();
        });
        document.getElementById('exec-btn-next').addEventListener('click', async () => {
            await this.execCache.nextPage();
            this.renderExecutionsTable();
            this.updateExecPaginationUI();
        });

        // Hooks
        document.getElementById('form-create-hook').addEventListener('submit', (e) => this.createHook(e));
        document.getElementById('form-edit-hook').addEventListener('submit', (e) => this.submitEditHook(e));
        document.getElementById('edit-hook-cancel').addEventListener('click', () => {
            document.getElementById('edit-hook-modal').classList.add('hidden');
        });

        // Parameters modal
        document.getElementById('form-add-param').addEventListener('submit', (e) => this.addParameter(e));
        document.getElementById('params-modal-close').addEventListener('click', () => {
            document.getElementById('params-modal').classList.add('hidden');
        });

        // Execution detail modal
        document.getElementById('execution-modal-close').addEventListener('click', () => {
            document.getElementById('execution-modal').classList.add('hidden');
        });

        // Keys
        document.getElementById('form-create-apikey').addEventListener('submit', (e) => this.createApiKey(e));
        document.getElementById('form-manage-rights').addEventListener('submit', (e) => this.manageKeyRights(e));
        document.getElementById('form-edit-key').addEventListener('submit', (e) => this.submitEditKey(e));
        document.getElementById('edit-key-cancel').addEventListener('click', () => {
            document.getElementById('edit-key-modal').classList.add('hidden');
        });
        document.getElementById('secret-reveal-close').addEventListener('click', () => {
            document.getElementById('secret-reveal-modal').classList.add('hidden');
        });
        document.getElementById('hook-result-close').addEventListener('click', () => {
            document.getElementById('hook-result-modal').classList.add('hidden');
        });

        // Settings
        document.getElementById('form-purge').addEventListener('submit', (e) => this.purgeExecutions(e));

        // Audit pagination
        document.getElementById('audit-btn-prev').addEventListener('click', () => {
            this.auditCache.prevPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        });
        document.getElementById('audit-btn-next').addEventListener('click', async () => {
            await this.auditCache.nextPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        });
    }
}

// Utils
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return unsafe
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDuration(ms) {
    if (typeof ms !== 'number') return '–';
    if (ms < 1000) return `${ms} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    window.app = new HookExecutorClient();
});
