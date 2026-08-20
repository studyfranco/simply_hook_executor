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
// Request signing — CANONICAL_V1, mandatory
// ───────────────────────────────────────────────────────────────────────────
//
// Every request this dashboard sends is signed. There is no unsigned path, no bearer-only path, and
// no per-key mode selection here: the browser is a first-party client whose key we provision
// ourselves, so it is held to the strongest posture the backend offers rather than the most
// permissive one it accepts.
//
// `api_keys.hmac_mode` has exactly one value, CANONICAL_V1 — the key-level `BODY_ONLY` mode this
// paragraph used to describe was retired once a hook's own `HMAC_ONLY` auth_mode began serving the
// keyless third-party webhook use case directly (no bearer key involved at all, which is the shape
// that kind of sender actually has). Signing CANONICAL_V1 here means the dashboard's own traffic is
// covered by the anti-replay window and the single-use guard in `src/replay.rs`.
//
// **What is mandatory is the signature, not the implementation that computes it.** `crypto.subtle`
// is exposed only in a secure context — HTTPS, or a `localhost` origin — and this daemon is
// routinely reached over plain HTTP at a LAN address, which is a deployment choice rather than an
// authentication one. Two implementations therefore stand behind one posture: Web Crypto where the
// browser offers it, and the self-contained `PureCrypto` below where it does not. They produce
// byte-identical signatures, so the backend cannot tell them apart and the security property does
// not depend on which one ran.

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
//
// Security note: this fallback is not constant-time, and it computes the MAC in interpreted JS.
// That is an accepted, explicit trade-off, and a narrow one — it runs *only* where `crypto.subtle`
// is absent, which is to say only on a plain-HTTP origin, where the request and every header it
// carries are already fully readable by anyone on the path. A timing side-channel in the browser is
// not the weak link in that deployment. HTTPS remains the recommended posture, and on HTTPS this
// code never executes.
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

    // Lowercase hex, matching Rust's `hex::encode`. Both signing paths render through this one
    // encoder, so they cannot disagree about the spelling of a digest they agree about the bytes of.
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

// Which implementation signs, and whether signing is possible at all.
//
// Web Crypto wins wherever it exists: it is constant-time and orders of magnitude faster. The
// fallback is consulted only in its absence, and only after `selfTest()` passes — an implementation
// that cannot reproduce a published vector must not be trusted with a real credential, and failing
// the login screen is better than emitting signatures the server will silently reject.
const SigningBackend = {
    // `crypto.subtle` is absent on any non-secure origin, which is exactly the case the fallback
    // exists for. Read as a getter rather than captured at load, so nothing depends on script order.
    get usesWebCrypto() {
        return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
    },

    // Memoized. The answer cannot change for the lifetime of the page, and a property consulted on
    // the login path should not recompute a MAC every time it is read.
    get available() {
        if (this._available === undefined) {
            this._available = this.usesWebCrypto || PureCrypto.selfTest();
        }
        return this._available;
    },

    get reason() {
        return (
            'This dashboard signs every request with HMAC-SHA256, and neither the Web Crypto API ' +
            'nor the built-in fallback is usable in this browser. Serving the dashboard over HTTPS ' +
            '(or from http://localhost:<port>) restores the preferred implementation.'
        );
    }
};

// Signs a request the way `src/middleware.rs` verifies it: HMAC-SHA256 over the canonical string
//
//     METHOD \n PATH_AND_QUERY \n TIMESTAMP \n RAW_BODY
//
// The newline delimiters, the full path *including any query string*, and the exact raw body all
// matter — see `signature_base` in `src/middleware.rs` for why each component is covered. The
// timestamp is seconds since the epoch and is sent verbatim as `X-Timestamp`, because the server
// feeds the header text straight into the MAC rather than re-parsing it.
class RequestSigner {
    constructor(signingSecret) {
        this.signingSecret = signingSecret || '';
        this.cryptoKey = null;
    }

    // Imports the secret once and caches the resulting non-extractable CryptoKey.
    //
    // Web Crypto path only — the fallback keys each HMAC directly from the secret's bytes, since
    // there is no opaque key object to hold on to.
    async key() {
        if (!this.cryptoKey) {
            this.cryptoKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(this.signingSecret),
                { name: 'HMAC', hash: 'SHA-256' },
                false, // non-extractable: the imported key cannot be read back out of the browser
                ['sign']
            );
        }
        return this.cryptoKey;
    }

    // Hex HMAC-SHA256 of `message` under the signing secret.
    //
    // Two implementations, one output. Web Crypto is preferred wherever the browser exposes it;
    // `PureCrypto` covers the plain-HTTP origins where it does not exist at all. Both render through
    // `PureCrypto.toHex`, so the branch decides only *how* the MAC is computed and never how it is
    // spelled — the server sees the same 64 hex characters either way.
    async digest(message) {
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);

        if (SigningBackend.usesWebCrypto) {
            const signature = await crypto.subtle.sign('HMAC', await this.key(), messageBytes);
            return PureCrypto.toHex(new Uint8Array(signature));
        }

        return PureCrypto.toHex(
            PureCrypto.hmacSha256(encoder.encode(this.signingSecret), messageBytes)
        );
    }

    // The two signature headers for one request.
    //
    // Throws rather than returning null on failure. There is deliberately no "signing unavailable"
    // return value any more: the caller has no fallback to take, and a thrown error surfaces at the
    // one place that can act on it instead of turning into a request the server will reject with a
    // 401 the user cannot interpret.
    async headers(method, pathAndQuery, body) {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const canonical = `${method.toUpperCase()}\n${pathAndQuery}\n${timestamp}\n${body ?? ''}`;
        return {
            'X-Timestamp': timestamp,
            'X-Signature-256': `sha256=${await this.digest(canonical)}`
        };
    }
}

class HookExecutorClient {
    // One line per mode, swapped into `.auth-mode-hint` on `change` — see `syncHookAuthFields`.
    // Every mode's hint restates the §1 rule from the help drawer (a valid, permitted API key
    // always bypasses this entirely) so the fact is visible right where the choice is made, not
    // only inside the drawer someone has to think to open.
    static AUTH_MODE_HINTS = {
        CANONICAL_V1:
            '<strong>Keyless:</strong> refused (401). <strong>Keyed:</strong> a permitted key\'s ' +
            'signature, if it signs, is verified against the template below (or the service ' +
            'default). <em>A valid key with can_execute always works here regardless.</em>',
        API_KEY_ONLY:
            '<strong>Keyless:</strong> refused (401), identically to CANONICAL_V1. Documents that a ' +
            '<em>keyed</em> caller is expected to present the bearer key alone — it does not need to ' +
            'also sign. <em>A valid key with can_execute always works here regardless.</em>',
        HMAC_ONLY:
            '<strong>Keyless:</strong> accepted with a valid signature over the raw body alone, ' +
            'using this hook\'s own secret below — no timestamp, ' +
            '<strong>no anti-replay protection</strong>. <em>A valid key with can_execute bypasses ' +
            'this signature requirement entirely.</em>',
        NONE:
            '<strong>Keyless:</strong> accepted with no authentication at all — only when this ' +
            'deployment\'s REQUIRE_SIGNED_REQUESTS is false. <em>A valid key with can_execute still ' +
            'works here too, exactly as for every other mode.</em>'
    };

    constructor() {
        this.apiKey = localStorage.getItem('simply_hook_executor_key') || '';
        this.signer = new RequestSigner(localStorage.getItem('simply_hook_executor_signing_secret') || '');

        // Two distinct bases, because behind a reverse proxy they are genuinely different paths:
        //
        //   requestBase — where to SEND. Derived from where this page is served, so a dashboard
        //                 mounted at /hook_executor/ fetches /hook_executor/api/hooks without any
        //                 configuration at all.
        //   signingBase — what to SIGN. The path this daemon's own HTTP layer sees after a
        //                 prefix-stripping reverse proxy is done rewriting, which no amount of
        //                 introspection in the browser can discover — hence the override. Defaults
        //                 to '/api', the direct-access case where the two are identical.
        //
        // Signing the browser's own URL instead would break the moment a proxy strips a prefix:
        // the daemon would verify '/api/hooks' against a signature computed over
        // '/hook_executor/api/hooks'. (`OriginalUri` in src/middleware.rs only undoes Axum's own
        // internal `Router::nest` prefix-stripping — it has no visibility into a reverse proxy in
        // front of the process at all, so it cannot paper over this on the server side.)
        this.requestBase = HookExecutorClient.deriveRequestBase();
        this.signingBase = HookExecutorClient.normalizeBasePath(
            localStorage.getItem('simply_hook_executor_api_base') || ''
        );
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

        // Refuse before anything else if the page cannot sign at all. With the pure-JS fallback in
        // place this now means Web Crypto is absent *and* the fallback failed its own RFC 4231
        // vector — a broken build rather than an ordinary deployment — so it should fail loudly at
        // the login screen instead of letting the operator type credentials into a form that would
        // emit signatures the server rejects.
        if (!SigningBackend.available) {
            this.showLogin();
            this.showLoginError(SigningBackend.reason);
            document.getElementById('login-form').querySelectorAll('input, button')
                .forEach(el => { el.disabled = true; });
            return;
        }

        // A session needs *both* halves: the key names the caller, the secret proves it. A stored
        // key with no stored secret is a half-session from an older build and cannot sign, so it is
        // discarded rather than carried into a request that would 401.
        if (this.apiKey && this.signer.signingSecret) {
            await this.verifyAuth();
        } else if (this.apiKey) {
            // `handleAuthFailure` clears both halves and shows the login screen itself.
            this.handleAuthFailure();
        } else {
            this.showLogin();
        }
    }

    // ───────────────────────────────────────────────────────
    // Proxy-aware base paths
    // ───────────────────────────────────────────────────────

    /**
     * Cleans up a user-typed base path: trims it, guarantees exactly one leading slash, drops any
     * trailing one, and falls back to '/api' when blank. Idempotent, so re-normalizing a stored
     * value is harmless.
     */
    static normalizeBasePath(raw) {
        const trimmed = (raw || '').trim();
        if (!trimmed) return '/api';
        return `/${trimmed.replace(/^\/+/, '').replace(/\/+$/, '')}`;
    }

    /**
     * The prefix every request is sent to, derived from the directory this page is served from.
     *
     * Served at `/` this yields `/api` — byte-identical to the previous hardcoded value, so direct
     * (non-proxied) deployments behave exactly as before. Served at `/hook_executor/` it yields
     * `/hook_executor/api`, which is what makes a sub-path mount work with no configuration at all.
     *
     * This is the same directory-of-the-current-URL rule (RFC 3986 §5.3) the browser itself already
     * applies to resolve this page's own `<script src="app.js">` and `<link href="style.css">` —
     * both plain relative hrefs. That equivalence is what makes the "with or without a trailing
     * slash" requirement fall out for free rather than needing special-casing here: a bare-prefix
     * URL with no trailing slash (`/hook_executor`, not `/hook_executor/`) resolves a *relative*
     * script tag to `/app.js` at the domain root under the identical rule, so this function would
     * never even run — the page's own assets fail to load first, on every browser, independent of
     * anything in this file. A deployment that must support the bare-prefix form redirects it to the
     * trailing-slash form (a one-line Traefik rule, or any reverse proxy's default directory
     * behavior) before the page is ever served, exactly as it must already do for `style.css`.
     */
    static deriveRequestBase() {
        const path = window.location.pathname;
        // Everything up to and including the last '/': '/hook_executor/index.html' → '/hook_executor/',
        // '/' → '/'.
        const dir = path.slice(0, path.lastIndexOf('/') + 1) || '/';
        return `${dir}api`.replace(/\/{2,}/g, '/');
    }

    /**
     * Persists the API base path override and applies it to this session.
     *
     * Only signing is affected — where requests are *sent* stays derived from the page location.
     * The two are independent precisely because a prefix-stripping proxy makes them differ.
     */
    setApiBaseOverride(raw) {
        const normalized = HookExecutorClient.normalizeBasePath(raw);
        this.signingBase = normalized;
        if (normalized === '/api') {
            localStorage.removeItem('simply_hook_executor_api_base');
        } else {
            localStorage.setItem('simply_hook_executor_api_base', normalized);
        }
    }

    // ───────────────────────────────────────────────────────
    // Fetch Wrapper (Global 401 interceptor)
    // ───────────────────────────────────────────────────────
    async apiFetch(endpoint, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        // Two distinct targets built from the same endpoint: where the request is actually sent
        // (browser-relative, so it reaches this page's own reverse-proxy path) and what the
        // signature covers (the daemon's own view of its path — see the constructor for why a
        // prefix-stripping proxy makes these different). Signing must use `signingBase`, never
        // `requestBase`: the server canonicalizes against the request target *it* receives, which
        // has already had any reverse-proxy prefix stripped away.
        const requestPath = `${this.requestBase}${endpoint}`;
        const signedPath = `${this.signingBase}${endpoint}`;
        // `body` is signed byte-for-byte as sent; an absent body signs as the empty string, which
        // is what the backend uses for GET/DELETE without a payload.
        const body = options.body ?? '';

        try {
            // Signing is unconditional and happens before the request is built, so a signing
            // failure can never fall through into an unsigned request. `options.headers` is spread
            // first so a caller cannot accidentally override the three authentication headers.
            const headers = {
                'Content-Type': 'application/json',
                ...(options.headers || {}),
                'X-API-Key': this.apiKey,
                ...(await this.signer.headers(method, signedPath, body))
            };

            const res = await fetch(requestPath, { ...options, headers });

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
            // `GET /api/auth/me` is itself a signed CANONICAL_V1 request, so reaching the dashboard
            // proves the secret is correct — not merely that the key exists. The server's
            // `hmac_mode` is no longer consulted to pick a signing scheme: this client always signs
            // CANONICAL_V1, and a key configured otherwise is a key that cannot drive the dashboard.
            this.state.profile = await this.apiFetch('/auth/me');
            this.showDashboard();
            this.enforceRBACUI();
            this.loadInitialData();
        } catch (e) {
            // Interceptor handles logout
        }
    }

    async login(key, signingSecret) {
        // Both fields are mandatory. `required` on the inputs already covers the ordinary path;
        // this is the check that does not depend on markup staying correct.
        if (!key || !signingSecret) {
            this.showLoginError('An API key and its signing secret are both required.');
            return;
        }

        this.apiKey = key;
        this.signer = new RequestSigner(signingSecret);
        localStorage.setItem('simply_hook_executor_key', key);
        localStorage.setItem('simply_hook_executor_signing_secret', signingSecret);

        document.getElementById('login-error').classList.add('hidden');
        await this.verifyAuth();
    }

    // Shows a message on the login screen. Used for the two failures that happen before any request
    // is sent — no usable signing backend, and a half-filled form — which the 401 interceptor never
    // sees.
    showLoginError(message) {
        const box = document.getElementById('login-error');
        box.textContent = message;
        box.classList.remove('hidden');
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

        // A compact pill rather than a bare string: Master gets its own high-contrast variant, so
        // "who am I signed in as" is answerable at a glance rather than by reading a sentence.
        const badge = document.getElementById('identity-badge');
        badge.className = `identity-pill${p.is_master ? ' identity-pill-master' : ''}`;
        badge.innerHTML = p.is_master
            ? `<span class="identity-pill-dot"></span> MASTER <span class="identity-pill-name">${escapeHtml(p.name)}</span>`
            : `<span class="identity-pill-dot"></span> ${escapeHtml(p.name)} <span class="identity-pill-prefix">${escapeHtml(p.prefix)}...</span>`;

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
        document.getElementById('audit-tab-btn').style.display = p.is_master ? 'inline-block' : 'none';

        // The trash view (`?include_deleted=true`) is master-only server side
        // (`guard_master_for_deleted_view`), so the toggle is disabled rather than hidden — same
        // "visible but explained" treatment as `applyRunAsUserGuard` below.
        const showDeleted = document.getElementById('hooks-show-deleted');
        if (showDeleted) {
            showDeleted.disabled = !p.is_master;
            showDeleted.title = p.is_master ? '' : 'Only master API keys can view the hook trash';
            if (!p.is_master && showDeleted.checked) {
                showDeleted.checked = false;
                this.loadHooks();
            }
        }

        // A key with no executable hook has nothing to run.
        const canExecuteAny = p.is_master || (p.hook_permissions || []).some(h => h.can_execute);
        document.getElementById('run-hook-section').style.display = canExecuteAny ? 'block' : 'none';

        // Hooks Management is also reachable by a key that *owns* a hook: §3 ownership confers the
        // right to edit and delete it, and that is independent of holding a `can_manage` row. Owned
        // hooks are only known once the hook list loads, so `renderHooks` re-runs this.
        if (!canManageAnyHook && (this.state.hooks || []).some(h => h.is_owner)) {
            document.getElementById('hooks-tab-btn').style.display = 'inline-block';
        }

        // Assigning run_as_user is a privilege-escalation request and is master-only server side.
        // The field is disabled rather than merely hidden, so a non-master sees that the capability
        // exists and why it is unavailable, instead of wondering where it went.
        this.applyRunAsUserGuard();
        // R4: only Master may grant a global scope, so the toggles that request one are inert for
        // everyone else.
        this.applyGlobalScopeGuard();
        this.applyKeylessHooksGuard();
    }

    // Reflects RBAC_MODEL.md R4 in the key forms: "Only the Master key may grant `can_manage_keys`
    // or any resource-creation right."
    //
    // The create form *hides* the toggles, because a Parent has no decision to make there — every
    // key it mints is a Daughter, and offering a checkbox that can only be left unticked is an
    // invitation to a 403. The edit modal keeps them visible but disabled, because there a Parent
    // may legitimately need to *see* what the key it is editing already holds; R4 restricts granting
    // a scope, not looking at one.
    applyGlobalScopeGuard() {
        const isMaster = Boolean(this.state.profile?.is_master);

        const createGrid = document.getElementById('apikey-master-only-scopes');
        const createNote = document.getElementById('apikey-scopes-locked-note');
        if (createGrid && createNote) {
            createGrid.classList.toggle('hidden', !isMaster);
            createNote.classList.toggle('hidden', isMaster);
            if (!isMaster) {
                // Cleared as well as hidden: a stale tick from a previous Master session in the same
                // tab would otherwise still be read by `createApiKey`.
                document.getElementById('apikey-can-manage-keys').checked = false;
                document.getElementById('apikey-can-manage-hooks').checked = false;
            }
        }

        ['edit-key-can-manage-keys', 'edit-key-can-manage-hooks'].forEach(id => {
            const input = document.getElementById(id);
            if (input) {
                input.disabled = !isMaster;
                input.title = isMaster ? '' : 'Only the Master key may change this scope (R4)';
            }
        });
    }

    // A can_manage_keys holder must always sign, so "generate a signing secret" cannot be unchecked
    // once "Manage Keys" is — matching the 400 `create_api_key` would otherwise return, but caught
    // before the request is even sent. The canonical-template field is likewise hidden once no
    // secret will exist to compute one against: it has nothing to apply to.
    syncApiKeySigningFields() {
        const wantsManageKeys = document.getElementById('apikey-can-manage-keys').checked;
        const secretCheckbox = document.getElementById('apikey-generate-signing-secret');
        if (wantsManageKeys) {
            secretCheckbox.checked = true;
            secretCheckbox.disabled = true;
            secretCheckbox.title = 'can_manage_keys requires a signing secret';
        } else {
            secretCheckbox.disabled = false;
            secretCheckbox.title = '';
        }
        document.getElementById('apikey-canonical-template-group').classList.toggle('hidden', !secretCheckbox.checked);
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

    // Shows/hides the mode-dependent field groups on a hook's create or edit form and swaps in
    // that mode's one-line hint (`AUTH_MODE_HINTS`). `prefix` is `'hook'` for the create form or
    // `'edit-hook'` for the modal — every id below follows `${prefix}-auth-mode`,
    // `${prefix}-hmac-secret-group`, etc., so one function drives both without duplicating the
    // toggle logic.
    //
    // `canonical_template` is deliberately gated on CANONICAL_V1 alone, not API_KEY_ONLY too: the
    // field's own doc comment (`hook::Model::canonical_template`) is explicit that it is "consulted
    // only when a keyed caller invokes a hook whose AuthMode is AuthMode::CanonicalV1" — showing it
    // under API_KEY_ONLY would offer a control that is silently never read.
    syncHookAuthFields(prefix) {
        const modeSelect = document.getElementById(`${prefix}-auth-mode`);
        if (!modeSelect) return;
        const mode = modeSelect.value;
        const needsSecret = mode === 'HMAC_ONLY';
        const needsTemplate = mode === 'CANONICAL_V1';

        const toggle = (id, visible) => {
            const el = document.getElementById(id);
            if (el) el.classList.toggle('hidden', !visible);
        };
        toggle(`${prefix}-hmac-secret-group`, needsSecret);
        toggle(`${prefix}-hmac-transport-group`, needsSecret);
        toggle(`${prefix}-canonical-template-group`, needsTemplate);

        const secretInput = document.getElementById(`${prefix}-hmac-secret`);
        // Only the create form's secret is ever mandatory — the edit form's blank means "keep the
        // current one" (see `submitEditHook`), so it is never `required`.
        if (secretInput) secretInput.required = needsSecret && prefix === 'hook';

        const hint = document.getElementById(`${prefix}-auth-mode-hint`);
        if (hint) hint.innerHTML = HookExecutorClient.AUTH_MODE_HINTS[mode] || '';
    }

    // Greys out the `NONE` option on both hook forms' Auth Mode selects when this deployment's
    // `REQUIRE_SIGNED_REQUESTS` makes it unreachable keylessly anyway (`keyless_hooks_allowed`,
    // mirrored onto `MeResponse` so a non-master `can_manage_hooks` holder sees this too, not only
    // master via `GET /api/settings`). The option stays selectable — never removed — so an existing
    // hook already set to `NONE` still shows its real mode instead of silently substituting another
    // one; only *choosing* it going forward is discouraged, via `disabled` plus a tooltip.
    applyKeylessHooksGuard() {
        const allowed = this.state.profile?.keyless_hooks_allowed !== false;
        document.querySelectorAll('#hook-auth-mode option[value="NONE"], #edit-hook-auth-mode option[value="NONE"]')
            .forEach(opt => {
                opt.disabled = !allowed;
                opt.title = allowed ? '' : 'This deployment requires signed requests (REQUIRE_SIGNED_REQUESTS) — a NONE hook would never actually be reachable keylessly';
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
            const showDeleted = Boolean(document.getElementById('hooks-show-deleted')?.checked);
            const params = showDeleted ? '?include_deleted=true' : '';
            this.state.hooks = await this.apiFetch(`/hooks${params}`);
            this.renderHooksTable();
            // Re-run once the hooks are known: the Hooks tab is also reachable by a key that owns a
            // hook without holding any global scope, and ownership is only visible in this response.
            if (this.state.profile) this.enforceRBACUI();

            // The trash view is for browsing and restoring, not for picking a target to act on —
            // none of these three pickers should ever offer a hook that cannot actually be run,
            // searched for a history entry against, or granted rights on right now.
            const live = this.state.hooks.filter(h => !h.is_deleted);
            const byId = live.map(h => ({ value: h.id, label: h.name }));
            const byName = live.map(h => ({ value: h.name, label: h.name }));
            this.runHookCombobox.setOptions(live.filter(h => h.can_execute).map(h => ({ value: h.id, label: h.name })));
            this.execHookFilterCombobox.setOptions(byName);
            this.rightsHookCombobox.setOptions(byId);
        } catch (e) {}
    }

    async fetchExecutionsChunk(offset, limit) {
        const hookQ = document.getElementById('exec-hook-filter').value;
        const statusQ = document.getElementById('exec-status-filter').value;
        const keyQ = document.getElementById('exec-key-filter').value.trim();
        const since = HookExecutorClient.toRfc3339(document.getElementById('exec-since-filter').value);
        const until = HookExecutorClient.toRfc3339(document.getElementById('exec-until-filter').value);

        const params = new URLSearchParams({ limit, offset });
        if (hookQ) params.append('hook', hookQ);
        if (statusQ) params.append('status', statusQ);
        if (keyQ) params.append('api_key', keyQ);
        if (since) params.append('since', since);
        if (until) params.append('until', until);

        return await this.apiFetch(`/executions?${params.toString()}`);
    }

    clearExecutionFilters() {
        document.getElementById('exec-hook-filter').value = '';
        ['exec-key-filter', 'exec-since-filter', 'exec-until-filter'].forEach(id => { document.getElementById(id).value = ''; });
        document.getElementById('exec-status-filter').value = '';
        this.loadExecutions();
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

    // `<input type="datetime-local">` has no timezone of its own — the browser treats its value as
    // local time — so `new Date(...)` interprets it the same way, and `.toISOString()` is what
    // converts that into the UTC RFC 3339 string `parse_instant` on the server expects.
    static toRfc3339(datetimeLocalValue) {
        if (!datetimeLocalValue) return '';
        const d = new Date(datetimeLocalValue);
        return Number.isNaN(d.getTime()) ? '' : d.toISOString();
    }

    async fetchAuditLogsChunk(offset, limit) {
        const params = new URLSearchParams({ limit, offset });
        const action = document.getElementById('audit-action-filter').value.trim();
        const ip = document.getElementById('audit-ip-filter').value.trim();
        const apiKey = document.getElementById('audit-key-filter').value.trim();
        const since = HookExecutorClient.toRfc3339(document.getElementById('audit-since-filter').value);
        const until = HookExecutorClient.toRfc3339(document.getElementById('audit-until-filter').value);
        if (action) params.append('action', action);
        if (ip) params.append('client_ip', ip);
        if (apiKey) params.append('api_key', apiKey);
        if (since) params.append('since', since);
        if (until) params.append('until', until);
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

    clearAuditFilters() {
        ['audit-action-filter', 'audit-ip-filter', 'audit-key-filter', 'audit-since-filter', 'audit-until-filter']
            .forEach(id => { document.getElementById(id).value = ''; });
        this.loadAuditLogs();
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
        // Destructive confirmations are solid red; ordinary ones take the accent. Cancel is always
        // `.btn-secondary`, so the two never read as a matched pair of equally-weighted choices.
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
                // Enter confirms only a *non-destructive* action. A dialog that both auto-focuses
                // "Delete" and treats a bare Enter as agreement will eventually destroy something
                // for a user who was still typing when it opened, and will do it in the one place
                // where the action cannot be undone. Escape still cancels either way, so the safe
                // answer remains the reflexive one.
                //
                // Destructive dialogs are not left without a keyboard path: Cancel holds focus, so
                // Enter activates *it*, and Tab reaches Confirm in one step.
                if (e.key === 'Enter' && !danger) cleanup(true);
            };

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            modal.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeydown);
            // The safe choice takes focus when the consequence is irreversible.
            (danger ? cancelBtn : confirmBtn).focus();
        });
    }

    // The "?" auth-help side drawer: one shared instance opened from either hook form's Auth Mode
    // field. Closes on the backdrop, the × button, or Escape — the same three exits every other
    // overlay in this dashboard offers. Shares `#drawer-backdrop` with the key lineage drawer below
    // — only one drawer is ever open at once, so one backdrop element serves both.
    openAuthHelpDrawer() {
        document.getElementById('drawer-backdrop').classList.remove('hidden');
        document.getElementById('auth-help-drawer').classList.remove('hidden');
    }

    closeAuthHelpDrawer() {
        document.getElementById('drawer-backdrop').classList.add('hidden');
        document.getElementById('auth-help-drawer').classList.add('hidden');
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
            // Hidden outright rather than merely disabled: a greyed-out "Delete Selected" sitting
            // in the toolbar on every page load, with nothing selected, is a control offering an
            // action that is never actually available yet — simply_ip_vault's own batch bars do the
            // same. Only the button is hidden here, not its whole `.batch-actions` row (vault hides
            // the row too): the Hooks tab's row also carries the "Show deleted" toggle, which must
            // stay reachable regardless of selection — hiding the row would hide that control too.
            deleteBtn.classList.toggle('hidden', selectedSet.size === 0);
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
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No executions recorded.</td></tr>';
        } else {
            tbody.innerHTML = rows.map(e => `
                <tr>
                    <td><input type="checkbox" class="row-select" data-id="${e.id}"></td>
                    <td class="text-sm">${new Date(e.timestamp + 'Z').toLocaleString()}</td>
                    <td><strong>${escapeHtml(e.hook_name)}</strong></td>
                    <td class="text-sm">${e.api_key_name ? escapeHtml(e.api_key_name) : '<span class="text-muted">(keyless)</span>'}</td>
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
        const payloadGroup = document.getElementById('run-hook-payload-group');
        const payloadInput = document.getElementById('run-hook-payload-json');
        const payloadError = document.getElementById('run-hook-payload-error');
        const result = document.getElementById('run-hook-result');
        result.classList.add('hidden');
        payloadError.classList.add('hidden');

        if (!hook) {
            meta.classList.add('hidden');
            payloadGroup.classList.add('hidden');
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
                <div class="param-info-row">
                    <span class="font-mono text-sm">${escapeHtml(p.param_key)}${p.is_required && p.default_value === null ? ' <span>*</span>' : ''}</span>
                    <span class="text-muted text-sm">${p.default_value !== null ? 'default: ' + escapeHtml(p.default_value) : (p.is_required ? 'required' : 'optional')}${p.description ? ' · ' + escapeHtml(p.description) : ''}</span>
                </div>
            `).join('');
        }

        payloadGroup.classList.remove('hidden');
        payloadInput.value = hook.sample_payload_json || '{}';

        document.getElementById('btn-execute-hook').disabled = false;
        document.getElementById('btn-test-hook').disabled = false;
    }

    // Reads the live JSON payload editor. Returns `null` (and surfaces an inline error) on
    // malformed JSON or a non-object top level, rather than letting the request go out with a
    // parameter map the server would just reject anyway.
    collectRunParameters() {
        const payloadInput = document.getElementById('run-hook-payload-json');
        const payloadError = document.getElementById('run-hook-payload-error');
        payloadError.classList.add('hidden');
        const raw = payloadInput.value.trim();
        if (raw === '') return {};
        try {
            const parsed = JSON.parse(raw);
            if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
                throw new Error('Payload must be a JSON object');
            }
            return parsed;
        } catch (e) {
            payloadError.textContent = `Invalid JSON payload: ${e.message}`;
            payloadError.classList.remove('hidden');
            return null;
        }
    }

    // Builds the node for one captured stream. Returns a DOM *element*, never an HTML string.
    //
    // Hook `stdout`/`stderr`, resolved parameter values, and the dry-run command preview are the
    // one class of data in this UI an attacker controls end to end: whoever can execute a hook
    // chooses what the script prints, it is persisted verbatim in `executions.stdout`, and every
    // operator who later opens that record re-renders it. A payload such as
    // `<img src=x onerror=...>` would then run in a master key holder's session.
    //
    // `textContent` assigns rather than parses, so the payload is displayed as the literal text the
    // script emitted. Escaping into `innerHTML` would also be correct today, but it stays correct
    // only as long as nobody edits the template — assignment cannot be made unsafe by a later edit.
    outputBlock(label, content) {
        const group = document.createElement('div');
        group.className = 'output-group';

        const caption = document.createElement('span');
        caption.className = 'output-label';
        caption.textContent = label;

        const pre = document.createElement('pre');
        pre.className = 'output-block';
        if (content !== null && content !== undefined && content.length > 0) {
            pre.textContent = content;
        } else {
            const empty = document.createElement('span');
            empty.className = 'text-muted';
            empty.textContent = '(empty)';
            pre.appendChild(empty);
        }

        group.append(caption, pre);
        return group;
    }

    // Renders a result view (run panel or modal) into `container`.
    //
    // The split is deliberate and is the invariant worth keeping: `headerHtml` is markup this file
    // builds from its own literals plus already-escaped badge helpers, while everything the server
    // hands back — the blocking reason, the captured streams — arrives as pre-built nodes or plain
    // text and is assigned, never parsed. A caller therefore cannot accidentally route hook output
    // through the HTML path.
    renderResultView(container, { headerHtml = '', headerClass = 'result-header', noteText = null, errorText = null, blocks = [] }) {
        container.replaceChildren();

        if (headerHtml) {
            const header = document.createElement('div');
            header.className = headerClass;
            header.innerHTML = headerHtml;
            container.appendChild(header);
        }

        if (noteText) {
            const note = document.createElement('p');
            note.className = 'subtitle';
            note.textContent = noteText;
            container.appendChild(note);
        }

        // Server-supplied diagnostic text (`blocking_reason`, and the `[ERROR] Cannot execute
        // '<path>': ...` lines the executor produces), which embeds an operator-chosen script path.
        if (errorText) {
            const message = document.createElement('p');
            message.className = 'message error';
            message.textContent = errorText;
            container.appendChild(message);
        }

        for (const block of blocks) {
            container.appendChild(block);
        }
    }

    async executeHook(e) {
        e.preventDefault();
        const hookId = document.getElementById('run-hook-id').value;
        if (!hookId) {
            this.showToast('Select a hook first', 'error');
            return;
        }
        const parameters = this.collectRunParameters();
        if (parameters === null) return;

        const btn = document.getElementById('btn-execute-hook');
        btn.disabled = true;
        btn.textContent = 'Executing...';
        try {
            const res = await this.apiFetch(`/hooks/${hookId}/execute`, {
                method: 'POST',
                body: JSON.stringify({ parameters })
            });

            const panel = document.getElementById('run-hook-result');
            panel.classList.remove('hidden');
            this.renderResultView(panel, {
                headerHtml: `
                    ${this.statusBadge(res.status)}
                    <span class="text-sm text-muted">exit ${escapeHtml(res.exit_code === null ? '–' : res.exit_code)} · ${escapeHtml(formatDuration(res.duration_ms))}</span>
                `,
                blocks: [
                    this.outputBlock('stdout', res.stdout),
                    this.outputBlock('stderr', res.stderr)
                ]
            });
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
        const parameters = this.collectRunParameters();
        if (parameters === null) return;

        try {
            const res = await this.apiFetch(`/hooks/${hookId}/test`, {
                method: 'POST',
                body: JSON.stringify({ parameters })
            });

            const envRows = Object.entries(res.command.env)
                .map(([k, v]) => `${k}=${v}`).join('\n');
            const argList = res.command.args.length
                ? res.command.args.map((a, i) => `argv[${i + 1}] = ${a}`).join('\n')
                : '(none)';

            const panel = document.getElementById('run-hook-result');
            panel.classList.remove('hidden');
            this.renderResultView(panel, {
                headerHtml: `
                    <span class="badge ${res.would_execute ? 'badge-success' : 'badge-failed'}">
                        ${res.would_execute ? 'DRY RUN OK' : 'BLOCKED'}
                    </span>
                    <span class="text-sm text-muted">timeout ${escapeHtml(res.timeout_seconds)}s</span>
                    ${res.command.run_as_user ? this.privilegeBadge(res.command.run_as_user) : ''}
                `,
                errorText: res.blocking_reason || null,
                blocks: [
                    this.outputBlock('command', res.command.program),
                    this.outputBlock('positional arguments', argList),
                    this.outputBlock('environment', envRows)
                ]
            });
            this.showToast(res.would_execute ? 'Dry run resolved successfully' : 'Dry run blocked', res.would_execute ? 'success' : 'error');
        } catch (err) {}
    }

    async openExecutionModal(id) {
        try {
            const e = await this.apiFetch(`/executions/${id}`);
            const paramRows = Object.entries(e.parameters || {}).length
                ? Object.entries(e.parameters).map(([k, v]) => `${k} = ${v}`).join('\n')
                : '(none)';

            this.renderResultView(document.getElementById('execution-modal-body'), {
                headerClass: 'kv-grid',
                headerHtml: `
                    <div class="kv-item"><span class="kv-key">Hook</span><span class="kv-value">${escapeHtml(e.hook_name)}</span></div>
                    <div class="kv-item"><span class="kv-key">API Key</span><span class="kv-value">${e.api_key_name ? escapeHtml(e.api_key_name) : '<span class="text-muted">(keyless invocation)</span>'}</span></div>
                    <div class="kv-item"><span class="kv-key">Status</span><span class="kv-value">${this.statusBadge(e.status)}</span></div>
                    <div class="kv-item"><span class="kv-key">Exit code</span><span class="kv-value font-mono">${escapeHtml(e.exit_code === null ? '–' : e.exit_code)}</span></div>
                    <div class="kv-item"><span class="kv-key">Duration</span><span class="kv-value">${escapeHtml(formatDuration(e.duration_ms))}</span></div>
                    <div class="kv-item"><span class="kv-key">Started</span><span class="kv-value">${escapeHtml(new Date(e.timestamp + 'Z').toLocaleString())}</span></div>
                    <div class="kv-item"><span class="kv-key">Execution ID</span><span class="kv-value font-mono text-sm">${escapeHtml(e.id)}</span></div>
                `,
                blocks: [
                    this.outputBlock('parameters', paramRows),
                    this.outputBlock('stdout', e.stdout),
                    this.outputBlock('stderr', e.stderr)
                ]
            });
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

            this.showHookResultModal(`Dry Run — ${hook.name}`, {
                headerHtml: `
                    <span class="badge ${res.would_execute ? 'badge-success' : 'badge-failed'}">
                        ${res.would_execute ? 'WOULD EXECUTE' : 'BLOCKED'}
                    </span>
                    <span class="text-sm text-muted">timeout ${escapeHtml(res.timeout_seconds)}s</span>
                    ${res.command.run_as_user ? this.privilegeBadge(res.command.run_as_user) : ''}
                `,
                noteText: 'Nothing was executed — this is the command that would run.',
                errorText: res.blocking_reason || null,
                blocks: [
                    this.outputBlock('program', res.command.program),
                    this.outputBlock('positional arguments', argList),
                    this.outputBlock('environment', envRows)
                ]
            });
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

            this.showHookResultModal(`Execution — ${hook.name}`, {
                headerHtml: `
                    ${this.statusBadge(res.status)}
                    <span class="text-sm text-muted">exit ${escapeHtml(res.exit_code === null ? '–' : res.exit_code)} · ${escapeHtml(formatDuration(res.duration_ms))}</span>
                    ${hook.run_as_user ? this.privilegeBadge(hook.run_as_user) : ''}
                `,
                blocks: [
                    this.outputBlock('stdout', res.stdout),
                    this.outputBlock('stderr', res.stderr)
                ]
            });
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

    // `view` is the descriptor [`renderResultView`] takes, not an HTML string: the modal cannot be
    // handed raw markup, which is what keeps hook output off the parsing path by construction.
    showHookResultModal(title, view) {
        document.getElementById('hook-result-title').textContent = title;
        this.renderResultView(document.getElementById('hook-result-body'), view);
        document.getElementById('hook-result-modal').classList.remove('hidden');
    }

    // Mirrors `require_manage` in src/api.rs. Master, or the hook's owner, or the R2 conjunction:
    // global `can_manage_keys` AND a `can_manage` row on this specific hook.
    //
    // The middle route is why `h.can_manage` alone is not the test. A key that created a hook owns
    // it and may maintain it without being a Parent; a key handed a bare `can_manage` row without
    // `can_manage_keys` is a Daughter, which "may manage resources: Never" — the row on its own buys
    // nothing, and offering it an enabled Edit button would only produce a 403.
    canEditHook(h) {
        const p = this.state.profile;
        if (!p) return false;
        return Boolean(p.is_master || h.is_owner || (p.can_manage_keys && h.can_manage));
    }

    // Mirrors `require_lifecycle_authority`: §3 restricts deleting and renaming to Master and the
    // designated owner. Holding manage rights confers no lifecycle authority — "a parent that merely
    // uses a resource must not be able to delete it."
    canDeleteHook(h) {
        const p = this.state.profile;
        if (!p) return false;
        return Boolean(p.is_master || h.is_owner);
    }

    // One badge per keyless auth_mode, colored the same way the help drawer groups them: a neutral
    // scope badge for the two "standard API key" values, warning-colored for HMAC_ONLY (the mode
    // with no anti-replay protection), and success-colored for NONE (fully open, when reachable).
    hookAuthModeBadge(mode) {
        const labels = {
            CANONICAL_V1: ['badge-scope', 'Signed'],
            API_KEY_ONLY: ['badge-scope', 'Bearer'],
            HMAC_ONLY: ['badge-timeout', 'Webhook HMAC'],
            NONE: ['badge-success', 'Public']
        };
        const [cls, label] = labels[mode] || ['badge-scope', escapeHtml(mode)];
        return `<span class="badge ${cls}" title="${escapeHtml(mode)}">${label}</span>`;
    }

    renderHooksTable() {
        const tbody = document.getElementById('hooks-table-body');

        if (this.state.hooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No hooks defined.</td></tr>';
        } else {
            tbody.innerHTML = this.state.hooks.map(h => {
                // A trashed hook cannot be executed, edited, or have its parameters touched — the
                // only actions left are Restore and a permanent (hard) delete, both master-only,
                // matching `restore_hook`/`delete_hook?hard=true` server-side.
                if (h.is_deleted) {
                    const isMaster = Boolean(this.state.profile?.is_master);
                    return `
                    <tr class="row-deleted">
                        <td></td>
                        <td><strong>${escapeHtml(h.name)}</strong> <span class="badge badge-timeout" title="Deleted ${h.deleted_at ? escapeHtml(h.deleted_at) : ''}${h.deleted_by ? ' by ' + escapeHtml(h.deleted_by) : ''}">Trashed</span></td>
                        <td class="font-mono text-sm truncate">${escapeHtml(h.script_path)}</td>
                        <td>${this.privilegeBadge(h.run_as_user)}</td>
                        <td class="text-sm">${h.default_timeout_seconds}s</td>
                        <td>${this.hookAuthModeBadge(h.auth_mode)}</td>
                        <td class="text-sm">${h.parameters.length}</td>
                        <td class="text-muted text-sm">–</td>
                        <td>
                            <div class="flex gap-2">
                                <button class="btn btn-sm btn-secondary" onclick="window.app.restoreHook('${h.id}')" ${isMaster ? '' : 'disabled'}
                                    title="${isMaster ? 'Restore this hook out of the trash' : 'Master keys only'}">Restore</button>
                                <button class="btn btn-sm btn-danger" onclick="window.app.hardDeleteHook('${h.id}')" ${isMaster ? '' : 'disabled'}
                                    title="${isMaster ? 'Permanently drop this hook and its full history — cannot be undone' : 'Master keys only'}">Purge</button>
                            </div>
                        </td>
                    </tr>`;
                }

                const editable = this.canEditHook(h);
                const deletable = this.canDeleteHook(h);
                const editHint = editable
                    ? 'Edit this hook'
                    : 'Requires being the hook owner, or Manage Keys plus a Manage grant on this hook';
                const deleteHint = deletable
                    ? 'Delete this hook'
                    : 'Only the hook owner or the Master key may delete a hook (§3)';

                const rights = [
                    h.is_owner ? '<span class="badge badge-scope badge-scope-master" title="You are answerable for this hook: you may edit, rename and delete it">Owner</span>' : '',
                    h.can_execute ? '<span class="badge badge-scope">Execute</span>' : '',
                    h.can_manage ? '<span class="badge badge-scope">Manage</span>' : '',
                    h.can_view_execution ? '<span class="badge badge-scope" title="May read this hook\'s execution history">History</span>' : ''
                ].filter(Boolean).join('') || '<span class="text-muted text-sm">None</span>';

                return `
                <tr>
                    <td>${deletable ? `<input type="checkbox" class="row-select" data-id="${h.id}">` : ''}</td>
                    <td><strong>${escapeHtml(h.name)}</strong></td>
                    <td class="font-mono text-sm truncate">${escapeHtml(h.script_path)}</td>
                    <td>${this.privilegeBadge(h.run_as_user)}</td>
                    <td class="text-sm">${h.default_timeout_seconds}s</td>
                    <td>${this.hookAuthModeBadge(h.auth_mode)}</td>
                    <td class="text-sm">${h.parameters.length}</td>
                    <td><div class="scope-badges">${rights}</div></td>
                    <td>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="window.app.testHookFromTable('${h.id}')" ${h.can_execute ? '' : 'disabled'}
                                title="${h.can_execute ? 'Dry run: resolve the command without executing it' : 'Requires execute permission'}">Test</button>
                            <button class="btn btn-sm btn-primary" onclick="window.app.launchHookFromTable('${h.id}')" ${h.can_execute ? '' : 'disabled'}
                                title="${h.can_execute ? 'Execute this hook for real' : 'Requires execute permission'}">Launch</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.showHookLogs('${h.id}')">Logs</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openParamsModal('${h.id}')" ${editable ? '' : 'disabled'} title="${editHint}">Parameters</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openEditHookModal('${h.id}')" ${editable ? '' : 'disabled'} title="${editHint}">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="window.app.deleteHook('${h.id}')" ${deletable ? '' : 'disabled'} title="${deleteHint}">Delete</button>
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

    async restoreHook(id) {
        try {
            await this.apiFetch(`/hooks/${id}/restore`, { method: 'POST' });
            this.showToast('Hook restored from the trash', 'success');
            this.loadHooks();
        } catch (e) {}
    }

    async hardDeleteHook(id) {
        const hook = this.state.hooks.find(h => h.id === id);
        const ok = await this.showConfirmModal({
            title: 'Permanently Delete Hook',
            message: `Permanently delete "${hook ? hook.name : id}" and its entire execution history? This cannot be undone.`,
            confirmText: 'Purge Permanently',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/hooks/${id}?hard=true`, { method: 'DELETE' });
            this.showToast('Hook permanently deleted', 'success');
            this.loadHooks();
        } catch (e) {}
    }

    async purgeDeletedHooksNow() {
        const ok = await this.showConfirmModal({
            title: 'Purge Deleted Hooks',
            message: 'Permanently drop every trashed hook past the configured retention window, along with its full execution history? This cannot be undone.',
            confirmText: 'Purge',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch('/system/purge-hooks', { method: 'POST' });
            this.showToast(`Purged ${res.purged} deleted hook(s)`, 'success');
            this.loadHooks();
        } catch (e) {}
    }

    // Mirrors `executor::build_command_plan` well enough to preview it — advisory only, computed
    // entirely client-side, and never consulted by anything that actually runs a hook. Real
    // parameter values come from whatever the sample payload's own top-level keys supply; a
    // declared parameter absent from the sample falls back to its own `default_value`, and one with
    // neither renders as a `<key>` placeholder so the gap is visible rather than silently blank.
    //
    // `declaredParams` is `[]` on the create form (nothing is declared yet — parameters are added
    // after creation, through the Parameters modal), so the preview there is just the command and
    // elevation with no arguments, which is still the accurate answer for that moment.
    static computeCommandPreview(scriptPath, runAsUser, declaredParams, samplePayloadRaw) {
        let sample = {};
        if (samplePayloadRaw && samplePayloadRaw.trim()) {
            try {
                const parsed = JSON.parse(samplePayloadRaw);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) sample = parsed;
            } catch {
                // Invalid JSON: preview degrades to declared defaults/placeholders rather than
                // erroring — the textarea's own validation (server-side, on submit) is what
                // actually enforces well-formedness.
            }
        }

        const resolved = declaredParams.map(p => {
            const key = p.param_key;
            if (Object.prototype.hasOwnProperty.call(sample, key)) return [key, String(sample[key])];
            if (p.default_value !== null && p.default_value !== undefined) return [key, p.default_value];
            return [key, `<${key}>`];
        });

        const quote = (v) => `"${String(v).replace(/"/g, '\\"')}"`;
        const path = scriptPath && scriptPath.trim() ? scriptPath.trim() : '<script_path>';
        const argv = resolved.map(([, v]) => quote(v));
        let command = runAsUser && runAsUser.trim()
            ? `sudo -n -u ${runAsUser.trim()} -- ${path}`
            : path;
        if (argv.length) command += ` ${argv.join(' ')}`;

        const envLines = resolved.map(([k, v]) => `HOOK_PARAM_${k.toUpperCase()}=${quote(v)}`);
        return envLines.length ? `${envLines.join('\n')}\n${command}` : command;
    }

    // Recomputes and renders one form's preview box. `prefix` follows the same
    // `${prefix}-script-path`/`${prefix}-run-as-user`/`${prefix}-sample-payload` convention as
    // `syncHookAuthFields`, except the create form's fields have no `hook-` *value* prefix doubled
    // (they are simply `hook-script-path` etc.) — `fieldPrefix` and `hookId` are threaded through
    // separately because the create form has no backing hook to read declared parameters from.
    renderCommandPreview(fieldPrefix, previewId, hookId) {
        const scriptPath = document.getElementById(`${fieldPrefix}-script-path`)?.value || '';
        const runAsUser = document.getElementById(`${fieldPrefix}-run-as-user`)?.value || '';
        const sampleRaw = document.getElementById(`${fieldPrefix}-sample-payload`)?.value || '';
        const hook = hookId ? this.state.hooks.find(h => h.id === hookId) : null;
        const declaredParams = hook ? hook.parameters : [];
        const preview = document.getElementById(previewId);
        if (preview) preview.textContent = HookExecutorClient.computeCommandPreview(scriptPath, runAsUser, declaredParams, sampleRaw);
    }

    // Builds the auth-mode slice of a hook create/update payload from whichever form `prefix`
    // names. Shared because the two forms carry the same fields under the same suffix convention —
    // see `syncHookAuthFields`. `forCreate` governs whether `hmac_secret` is mandatory-if-visible
    // (create, where there is no existing secret to fall back to) versus opt-in (edit, where a
    // blank field means "keep the current one" and must be omitted rather than sent as `""`, which
    // would instead clear it).
    collectHookAuthPayload(prefix, forCreate) {
        const mode = document.getElementById(`${prefix}-auth-mode`).value;
        const payload = { auth_mode: mode };

        if (mode === 'HMAC_ONLY') {
            const secret = document.getElementById(`${prefix}-hmac-secret`).value;
            if (forCreate || secret !== '') payload.hmac_secret = secret;
            payload.signature_header = document.getElementById(`${prefix}-signature-header`).value;
            payload.signature_prefix = document.getElementById(`${prefix}-signature-prefix`).value;
        }
        if (mode === 'CANONICAL_V1') {
            payload.canonical_template = document.getElementById(`${prefix}-canonical-template`).value;
        }
        return payload;
    }

    async createHook(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('hook-name').value,
            script_path: document.getElementById('hook-script-path').value,
            default_timeout_seconds: parseInt(document.getElementById('hook-timeout').value, 10),
            // Blank means "no elevation"; the backend normalizes it to NULL.
            run_as_user: document.getElementById('hook-run-as-user').value.trim() || null,
            description: document.getElementById('hook-description').value || null,
            sample_payload_json: document.getElementById('hook-sample-payload').value || null,
            ...this.collectHookAuthPayload('hook', true)
        };
        try {
            await this.apiFetch('/hooks', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-create-hook').reset();
            document.getElementById('hook-timeout').value = 30;
            document.getElementById('hook-auth-mode').value = 'CANONICAL_V1';
            this.syncHookAuthFields('hook');
            this.renderCommandPreview('hook', 'hook-command-preview', null);
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

        document.getElementById('edit-hook-auth-mode').value = h.auth_mode;
        // The secret itself is never returned — see `hook::Model::hmac_secret`'s doc comment — so
        // this field always starts blank ("leave blank to keep the current secret"), and only its
        // *configured* status is shown.
        document.getElementById('edit-hook-hmac-secret').value = '';
        document.getElementById('edit-hook-hmac-secret-status').textContent = h.hmac_secret_configured
            ? 'A secret is currently configured. Enter a new value to rotate it.'
            : 'No secret is configured yet — required before this mode can accept a keyless caller.';
        document.getElementById('edit-hook-signature-header').value = h.signature_header || '';
        document.getElementById('edit-hook-signature-prefix').value = h.signature_prefix || '';
        document.getElementById('edit-hook-canonical-template').value = h.canonical_template || '';
        document.getElementById('edit-hook-sample-payload').value = h.sample_payload_json || '';
        this.syncHookAuthFields('edit-hook');
        this.renderCommandPreview('edit-hook', 'edit-hook-command-preview', h.id);

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
            description: document.getElementById('edit-hook-description').value,
            // "" clears it (backend convention shared with canonical_template etc.); omitting is
            // not an option here since the field is always sent, matching run_as_user/description.
            sample_payload_json: document.getElementById('edit-hook-sample-payload').value,
            ...this.collectHookAuthPayload('edit-hook', false)
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
        this.cancelParamEdit();
        this.renderParamsTable(hook);
        this.renderParamsModalPreview(hook);
        document.getElementById('params-modal').classList.remove('hidden');
    }

    // The Parameters modal has no script_path/sample_payload *inputs* of its own — script_path is
    // edited on the hook itself, and the sample lives on the Sample JSON Payload field there too —
    // so this reads both straight from the hook object rather than from form fields, unlike
    // `renderCommandPreview`.
    renderParamsModalPreview(hook) {
        const preview = document.getElementById('params-modal-command-preview');
        if (preview) {
            preview.textContent = HookExecutorClient.computeCommandPreview(
                hook.script_path, hook.run_as_user, hook.parameters, hook.sample_payload_json || ''
            );
        }
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
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-secondary" onclick="window.app.editParameter('${hook.id}', '${p.id}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteParameter('${hook.id}', '${p.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    // Loads one parameter's fields into the shared form and flips it into edit mode. `param_key` is
    // not part of `UpdateParameterPayload` at all — it is the row's identity, not an editable field
    // — so the key input is disabled rather than merely pre-filled, matching how
    // `applyRunAsUserGuard` disables a field the caller cannot use rather than leaving it silently
    // ineffective.
    editParameter(hookId, paramId) {
        const hook = this.state.hooks.find(h => h.id === hookId);
        const param = hook && hook.parameters.find(p => p.id === paramId);
        if (!param) return;

        document.getElementById('param-edit-id').value = paramId;
        document.getElementById('param-key').value = param.param_key;
        document.getElementById('param-key').disabled = true;
        document.getElementById('param-default').value = param.default_value ?? '';
        document.getElementById('param-description').value = param.description || '';
        document.getElementById('param-required').checked = param.is_required;

        document.getElementById('param-submit-btn').textContent = 'Save Changes';
        document.getElementById('param-cancel-edit-btn').classList.remove('hidden');
    }

    cancelParamEdit() {
        document.getElementById('form-add-param').reset();
        document.getElementById('param-edit-id').value = '';
        document.getElementById('param-key').disabled = false;
        document.getElementById('param-required').checked = true;
        document.getElementById('param-submit-btn').textContent = 'Add Parameter';
        document.getElementById('param-cancel-edit-btn').classList.add('hidden');
    }

    async addParameter(e) {
        e.preventDefault();
        const hookId = document.getElementById('params-modal-hook-id').value;
        const editId = document.getElementById('param-edit-id').value;
        const defaultValue = document.getElementById('param-default').value;
        const description = document.getElementById('param-description').value || null;
        const isRequired = document.getElementById('param-required').checked;
        const defaultOrNull = defaultValue === '' ? null : defaultValue;

        try {
            if (editId) {
                await this.apiFetch(`/hooks/${hookId}/parameters/${editId}`, {
                    method: 'PUT',
                    body: JSON.stringify({ description, default_value: defaultOrNull, is_required: isRequired })
                });
                this.showToast('Parameter updated', 'success');
            } else {
                await this.apiFetch(`/hooks/${hookId}/parameters`, {
                    method: 'POST',
                    body: JSON.stringify({
                        param_key: document.getElementById('param-key').value,
                        description,
                        default_value: defaultOrNull,
                        is_required: isRequired
                    })
                });
                this.showToast('Parameter added', 'success');
            }
            this.cancelParamEdit();
            await this.loadHooks();
            const hook = this.state.hooks.find(h => h.id === hookId);
            if (hook) { this.renderParamsTable(hook); this.renderParamsModalPreview(hook); }
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
            this.cancelParamEdit();
            await this.loadHooks();
            const hook = this.state.hooks.find(h => h.id === hookId);
            if (hook) { this.renderParamsTable(hook); this.renderParamsModalPreview(hook); }
        } catch (e) {}
    }

    // ───────────────────────────────────────────────────────
    // JSON Payload Extractor
    // ───────────────────────────────────────────────────────
    openJsonExtractorModal() {
        document.getElementById('json-extractor-input').value = '';
        document.getElementById('json-extractor-error').classList.add('hidden');
        document.getElementById('json-extractor-results').innerHTML = '';
        document.getElementById('json-extractor-modal').classList.remove('hidden');
    }

    // Parses the pasted sample payload and lists its top-level keys as candidate parameters. Only
    // flat string/number/boolean values are offered directly — the same shape
    // `executor::coerce_param_value` accepts — because a parameter value is a flat string in the
    // environment and on argv; a nested object or array is shown for context but cannot become one
    // without picking a leaf field out of it by hand instead.
    parseJsonExtractor() {
        const raw = document.getElementById('json-extractor-input').value;
        const errorBox = document.getElementById('json-extractor-error');
        const results = document.getElementById('json-extractor-results');
        errorBox.classList.add('hidden');
        results.innerHTML = '';

        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            errorBox.textContent = `Invalid JSON: ${e.message}`;
            errorBox.classList.remove('hidden');
            return;
        }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            errorBox.textContent = 'The sample payload must be a JSON object at the top level.';
            errorBox.classList.remove('hidden');
            return;
        }

        const hookId = document.getElementById('params-modal-hook-id').value;
        const hook = this.state.hooks.find(h => h.id === hookId);
        const existingKeys = new Set((hook ? hook.parameters : []).map(p => p.param_key));
        const entries = Object.entries(parsed);
        if (entries.length === 0) {
            results.innerHTML = '<p class="text-muted text-sm">The payload has no top-level keys.</p>';
            return;
        }

        results.innerHTML = `
            <table class="data-table">
                <thead><tr><th>Key</th><th>Sample Value</th><th>HOOK_PARAM_*</th><th></th></tr></thead>
                <tbody>
                    ${entries.map(([key, value]) => {
                        const flat = value === null || ['string', 'number', 'boolean'].includes(typeof value);
                        const valid = flat && executorIsValidParamKey(key);
                        const already = existingKeys.has(key);
                        const preview = flat ? String(value) : `<span class="text-muted">${Array.isArray(value) ? '[array]' : '{object}'} — pick a leaf field instead</span>`;
                        let action;
                        if (already) {
                            action = '<span class="text-muted text-sm">Already declared</span>';
                        } else if (!flat) {
                            action = '<span class="text-muted text-sm">Not a flat value</span>';
                        } else if (!valid) {
                            action = `<span class="text-muted text-sm" title="Must match [A-Za-z_][A-Za-z0-9_]*">Invalid key name</span>`;
                        } else {
                            action = `<button type="button" class="btn btn-sm btn-primary" onclick="window.app.addParameterFromExtractor(${JSON.stringify(key)}, ${JSON.stringify(String(value))})">Add</button>`;
                        }
                        return `
                        <tr>
                            <td class="font-mono">${escapeHtml(key)}</td>
                            <td class="font-mono text-sm truncate">${flat ? escapeHtml(preview) : preview}</td>
                            <td class="font-mono text-sm text-muted">HOOK_PARAM_${escapeHtml(key.toUpperCase())}</td>
                            <td>${action}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>
        `;
    }

    // Creates a parameter directly from an extractor row: required, defaulted to the sample's own
    // value (the common case — a webhook resending the same shape every time) so the form does not
    // have to be reopened and refilled by hand for each key picked.
    async addParameterFromExtractor(key, sampleValue) {
        const hookId = document.getElementById('params-modal-hook-id').value;
        try {
            await this.apiFetch(`/hooks/${hookId}/parameters`, {
                method: 'POST',
                body: JSON.stringify({
                    param_key: key,
                    description: null,
                    default_value: sampleValue,
                    is_required: true
                })
            });
            this.showToast(`Parameter '${key}' added`, 'success');
            await this.loadHooks();
            const hook = this.state.hooks.find(h => h.id === hookId);
            if (hook) {
                this.renderParamsTable(hook);
                this.renderParamsModalPreview(hook);
                this.parseJsonExtractor();
            }
        } catch (e) {}
    }

    // ───────────────────────────────────────────────────────
    // Rendering — API keys
    // ───────────────────────────────────────────────────────
    renderKeysTable() {
        const tbody = document.getElementById('apikeys-table-body');
        if (this.state.apiKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No API keys.</td></tr>';
        } else {
            tbody.innerHTML = this.state.apiKeys.map(k => `
                <tr>
                    <td><input type="checkbox" class="row-select" data-id="${k.id}"></td>
                    <td><strong>${escapeHtml(k.name)}</strong><div class="text-muted text-sm font-mono">${escapeHtml(k.prefix)}...</div></td>
                    <td>${this.hmacModeBadge(k)}</td>
                    <td class="font-mono text-sm">${escapeHtml(k.bound_ips || '-')}</td>
                    <td class="text-sm">${k.max_concurrent_jobs}</td>
                    <td>${this.renderKeyScopes(k)}</td>
                    <td>
                        <div class="flex gap-2">
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openEditKeyModal('${k.id}')">Edit</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.openLineageDrawer('${k.id}')" title="Show this key's parent/child lineage">Lineage</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateKey('${k.id}')" title="Replace the X-API-Key bearer credential only; the signing secret is unchanged">Regenerate Key</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateSecret('${k.id}')" title="Replace the HMAC signing secret only; the bearer key is unchanged">Regenerate Secret</button>
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

    // ───────────────────────────────────────────────────────
    // Key Lineage Drawer
    // ───────────────────────────────────────────────────────
    // RBAC_MODEL.md R3: "parent_key_id exists solely for cascading deletion and visibility scoping"
    // — display only here too, consulted by no guard. Built entirely from `this.state.apiKeys`
    // (already scoped to what this caller may see per §4), never a separate lineage endpoint: a
    // parent's own subtree is exactly the set of keys it can already list.
    openLineageDrawer(id) {
        const byId = new Map(this.state.apiKeys.map(k => [k.id, k]));
        const target = byId.get(id);
        if (!target) return;

        // Ancestors: walk parent_key_id up to the root (or to the point visibility stops).
        const ancestors = [];
        let cursor = target;
        while (cursor && cursor.parent_key_id) {
            const parent = byId.get(cursor.parent_key_id);
            ancestors.unshift(parent || { id: cursor.parent_key_id, name: '(not visible / deleted)', _ghost: true });
            cursor = parent;
        }

        // Direct children only, one level — a full descendant tree would need every generation's
        // permission to be visible too, which is not guaranteed for a Parent looking at its own
        // subtree from the middle rather than the root.
        const children = this.state.apiKeys.filter(k => k.parent_key_id === id);

        const row = (k, depth, current) => `
            <div class="lineage-row" style="padding-left: ${depth * 1.25}rem">
                ${depth > 0 ? '<span class="lineage-connector">↳</span>' : ''}
                <span class="${current ? 'lineage-current' : ''}">${escapeHtml(k.name)}</span>
                ${k.is_master ? '<span class="badge badge-scope badge-scope-master">Master</span>' : ''}
                ${k._ghost ? '<span class="text-muted text-sm">(outside your visibility)</span>' : ''}
            </div>`;

        const body = [
            ancestors.length
                ? `<h4>Ancestors</h4>${ancestors.map((k, i) => row(k, i, false)).join('')}`
                : '<p class="text-muted text-sm">No parent — this key was minted directly by Master at bootstrap, or its creator is not visible to you.</p>',
            row(target, ancestors.length, true),
            children.length
                ? `<h4 class="mt-4">Direct children</h4>${children.map(k => row(k, ancestors.length + 1, false)).join('')}`
                : '<p class="text-muted text-sm mt-4">No keys created by this one.</p>'
        ].join('');

        document.getElementById('key-lineage-title').textContent = `Lineage — ${target.name}`;
        document.getElementById('key-lineage-body').innerHTML = body;
        document.getElementById('drawer-backdrop').classList.remove('hidden');
        document.getElementById('key-lineage-drawer').classList.remove('hidden');
    }

    closeLineageDrawer() {
        document.getElementById('drawer-backdrop').classList.add('hidden');
        document.getElementById('key-lineage-drawer').classList.add('hidden');
    }

    // `api_keys.hmac_mode` has exactly one value now — `BODY_ONLY` was retired in favor of a hook's
    // own `HMAC_ONLY` mode for keyless third-party senders (see AGENT.MD's HMAC Signature Protocol
    // section) — so the badge is about the one thing that still varies per key: whether it overrides
    // the service-wide canonical template.
    hmacModeBadge(k) {
        if (k.canonical_template) {
            return `<span class="badge badge-timeout" title="Verified against a custom canonical_template, not the service default">CANONICAL_V1 (custom)</span>`;
        }
        return '<span class="badge badge-scope" title="Signs method + path + timestamp + body (service default)">CANONICAL_V1</span>';
    }

    // Global scope badges plus per-hook permission badges, each carrying a "×" to revoke that
    // specific grant.
    renderKeyScopes(k) {
        const scopes = [];
        if (k.is_master) scopes.push('<span class="badge badge-scope badge-scope-master">Master</span>');
        if (k.can_manage_keys) scopes.push('<span class="badge badge-scope">Manage Keys</span>');
        if (k.can_manage_hooks) scopes.push('<span class="badge badge-scope">Create Hooks</span>');

        const hookBadges = (k.hook_permissions || []).map(p => {
            // X = execute, M = manage, V = view history. `V` is listed last so an existing grant
            // reads the same as it did before this verb existed.
            const rights = [
                p.can_execute ? 'X' : '',
                p.can_manage ? 'M' : '',
                p.can_view_execution ? 'V' : ''
            ].filter(Boolean).join('') || 'none';
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
        // `is_master` is deliberately absent. It is not a field on the create payload at all
        // (RBAC_MODEL.md §5), and the payload type is `deny_unknown_fields` — so sending it, as this
        // form used to, made the deserializer reject the whole request with a 422 and no key was
        // ever created from this dashboard. `hmac_mode` is likewise absent: `HmacMode` has exactly
        // one variant now, so there is nothing left to choose.
        const generateSigningSecret = document.getElementById('apikey-generate-signing-secret').checked;
        const payload = {
            name: document.getElementById('apikey-name').value,
            bound_ips: document.getElementById('apikey-bound-ips').value,
            max_concurrent_jobs: parseInt(document.getElementById('apikey-max-jobs').value, 10),
            generate_signing_secret: generateSigningSecret,
            // A canonical_template is meaningless for a key with no signing secret to compute one
            // against — omitted entirely rather than sent as an ignored value, matching the field's
            // own visibility (see `syncApiKeySigningFields`).
            canonical_template: generateSigningSecret ? (document.getElementById('apikey-canonical-template').value || null) : null
        };

        // R4: only Master may grant a global scope. A non-Master caller omits the fields rather than
        // sending `false` — the backend refuses any *request* for a scope, and an explicit `false`
        // is indistinguishable from a request in a payload it has to reason about. Every key a
        // Parent mints is a Daughter, and saying nothing is the accurate way to ask for that.
        if (this.state.profile && this.state.profile.is_master) {
            payload.can_manage_keys = document.getElementById('apikey-can-manage-keys').checked;
            payload.can_manage_hooks = document.getElementById('apikey-can-manage-hooks').checked;
        }

        try {
            const res = await this.apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
            this.revealCredentials('API Key Created', res);
            document.getElementById('form-create-apikey').reset();
            document.getElementById('apikey-max-jobs').value = 10;
            this.syncApiKeySigningFields();
            this.loadKeys();
        } catch (err) {}
    }

    // One-time reveal of the credentials a key creation or rotation just minted. The signing
    // secret is stored encrypted and never returned again, so this modal is the only chance to
    // copy it — hence the deliberate friction of an "I have copied them" button.
    // `res` carries only the fields the calling endpoint actually regenerated — creation and full
    // rotation hand back all three; `regenerate-key` hands back only `plaintext_key`, and
    // `regenerate-secret` only `key_id`/`signing_secret` (both `None` fields are entirely absent
    // from the JSON, per the backend's `Option<String>` response fields). Each row is therefore
    // conditional on the field actually being present, not assumed.
    revealCredentials(title, res) {
        const field = (label, value, hint) => `
            <div class="form-group">
                <label>${escapeHtml(label)}</label>
                <code class="key-reveal-value">${escapeHtml(value)}</code>
                ${hint ? `<span class="text-muted text-sm">${escapeHtml(hint)}</span>` : ''}
            </div>`;

        document.getElementById('secret-reveal-title').textContent = title;
        document.getElementById('secret-reveal-body').innerHTML = [
            res.plaintext_key ? field('API Key', res.plaintext_key, 'Send as the X-API-Key header.') : '',
            res.key_id ? field('Key ID', res.key_id, 'Public identifier, for display and log correlation. Not a credential.') : '',
            res.signing_secret ? field('Signing Secret', res.signing_secret, 'Secret. Compute HMAC-SHA256 over the raw JSON body and send it as X-Signature-256: sha256=<hex>.') : ''
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

        // This endpoint writes the whole row: an unchecked box is a revocation, not "leave as is".
        const payload = {
            hook_id: hookId,
            can_execute: document.getElementById('manage-rights-execute').checked,
            can_manage: document.getElementById('manage-rights-manage').checked,
            can_view_execution: document.getElementById('manage-rights-view-execution').checked
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
        document.getElementById('edit-key-hmac-mode-display').innerHTML = this.hmacModeBadge(k);
        document.getElementById('edit-key-canonical-template').value = k.canonical_template || '';
        document.getElementById('edit-key-can-manage-keys').checked = k.can_manage_keys;
        document.getElementById('edit-key-can-manage-hooks').checked = k.can_manage_hooks;

        // A minimally-visible key (§4's shared-resource scope) arrives without its global flags at
        // all, so say "not visible" rather than rendering `undefined` as an unticked box — which
        // would read as a positive statement that the key holds neither scope.
        const note = document.getElementById('edit-key-scopes-locked-note');
        if (note) {
            const isMaster = Boolean(this.state.profile?.is_master);
            note.classList.toggle('hidden', isMaster);
            if (!isMaster) {
                const held = [
                    k.can_manage_keys ? 'Manage Keys' : '',
                    k.can_manage_hooks ? 'Create Hooks' : ''
                ].filter(Boolean).join(', ');
                note.textContent = k.partial
                    ? 'Global scopes are not visible for a key you only share a hook with.'
                    : `Global scopes (${held || 'none'}) are shown read-only: only the Master key may change them (R4).`;
            }
        }

        this.applyGlobalScopeGuard();
        document.getElementById('edit-key-modal').classList.remove('hidden');
    }

    async submitEditKey(e) {
        e.preventDefault();
        const id = document.getElementById('edit-key-id').value;
        const payload = {
            name: document.getElementById('edit-key-name').value,
            bound_ips: document.getElementById('edit-key-bound-ips').value,
            max_concurrent_jobs: parseInt(document.getElementById('edit-key-max-jobs').value, 10),
            // `hmac_mode` is deliberately absent: it is immutable after creation, and
            // `UpdateApiKeyPayload` no longer carries the field at all — naming it, even unchanged,
            // is refused by `deny_unknown_fields` before any handler runs.
            canonical_template: document.getElementById('edit-key-canonical-template').value
        };

        // Omitted entirely for a non-Master caller, for the same reason as in `createApiKey`: the
        // backend refuses a *request* for a global scope, and re-sending the value a key already
        // holds is still a request. Editing a Parent key's name would otherwise 403 on the scope it
        // already had, which looks like the rename being forbidden.
        if (this.state.profile && this.state.profile.is_master) {
            payload.can_manage_keys = document.getElementById('edit-key-can-manage-keys').checked;
            payload.can_manage_hooks = document.getElementById('edit-key-can-manage-hooks').checked;
        }

        try {
            await this.apiFetch(`/keys/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            this.showToast('Key updated', 'success');
            document.getElementById('edit-key-modal').classList.add('hidden');
            this.loadKeys();
        } catch (err) {}
    }

    // Independent regeneration: replaces only the bearer `X-API-Key`, leaving the signing pair
    // (`key_id` + `signing_secret`) untouched — a caller still signing with the existing secret
    // keeps working immediately, only the header value changes.
    async regenerateKey(id) {
        const ok = await this.showConfirmModal({
            title: 'Regenerate Key',
            message: "Regenerate this key's bearer X-API-Key? The old one stops working immediately. Its signing secret is unaffected.",
            confirmText: 'Regenerate',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/regenerate-key`, { method: 'POST' });
            this.revealCredentials('New Bearer API Key', res);
            this.showToast('API key regenerated — signing secret unchanged', 'success');
            this.loadKeys();
        } catch (e) {}
    }

    // The mirror image: replaces only the HMAC signing pair, leaving the bearer key untouched.
    async regenerateSecret(id) {
        const ok = await this.showConfirmModal({
            title: 'Regenerate Secret',
            message: "Regenerate this key's signing secret? The old one stops verifying immediately. Its bearer X-API-Key is unaffected.",
            confirmText: 'Regenerate',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/regenerate-secret`, { method: 'POST' });
            this.revealCredentials('New Signing Secret', res);
            this.showToast('Signing secret regenerated — API key unchanged', 'success');
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
            // Which peers may speak for a client decides what every bound_ips check compares
            // against, so an operator should be able to read it off the dashboard rather than the
            // daemon's environment.
            item('Trusted proxies', (s.trusted_proxies || []).length
                ? `<span class="font-mono text-sm">${escapeHtml(s.trusted_proxies.join(', '))}</span>`
                : '<span class="text-muted">(none — forwarding headers ignored, TCP peer is authoritative)</span>'),
            item('Log retention', s.log_retention_days > 0 ? `${s.log_retention_days} days` : 'disabled (kept forever)'),
            item('Deleted hook retention', s.deleted_hook_retention_days > 0 ? `${s.deleted_hook_retention_days} days` : 'disabled (kept forever)'),
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
        // Prefill the override from storage so a proxied deployment doesn't ask for it again on
        // every logout.
        document.getElementById('login-api-base').value =
            localStorage.getItem('simply_hook_executor_api_base') || '';

        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            // Applied before login(), since verifyAuth()'s very first request is already signed.
            this.setApiBaseOverride(document.getElementById('login-api-base').value);
            // Both trimmed: a trailing newline from a paste is invisible in a password field and
            // would otherwise become part of the key lookup or the HMAC key material.
            this.login(
                document.getElementById('login-key').value.trim(),
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
        document.getElementById('exec-key-filter').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.loadExecutions(); }
        });
        document.getElementById('exec-since-filter').addEventListener('change', () => this.loadExecutions());
        document.getElementById('exec-until-filter').addEventListener('change', () => this.loadExecutions());
        document.getElementById('exec-clear-filters-btn').addEventListener('click', () => this.clearExecutionFilters());

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
        document.getElementById('hooks-show-deleted').addEventListener('change', () => this.loadHooks());

        // Hook auth mode — one listener per form, driving the shared `syncHookAuthFields`. The
        // create form's hint is primed once here so it reads correctly before the first `change`.
        document.getElementById('hook-auth-mode').addEventListener('change', () => this.syncHookAuthFields('hook'));
        document.getElementById('edit-hook-auth-mode').addEventListener('change', () => this.syncHookAuthFields('edit-hook'));
        this.syncHookAuthFields('hook');

        // Live Command Preview — recomputed on every keystroke in the fields it depends on. The
        // create form has no backing hook (nothing declared yet); the edit form reads whichever
        // hook id its own hidden field currently names, so this keeps working across repeated opens
        // of the same modal for different hooks without re-binding anything.
        ['hook-script-path', 'hook-run-as-user', 'hook-sample-payload'].forEach(id => {
            document.getElementById(id).addEventListener('input', () => this.renderCommandPreview('hook', 'hook-command-preview', null));
        });
        ['edit-hook-script-path', 'edit-hook-run-as-user', 'edit-hook-sample-payload'].forEach(id => {
            document.getElementById(id).addEventListener('input', () =>
                this.renderCommandPreview('edit-hook', 'edit-hook-command-preview', document.getElementById('edit-hook-id').value));
        });
        this.renderCommandPreview('hook', 'hook-command-preview', null);

        // Auth-help drawer — either form's "?" trigger opens the one shared instance.
        ['hook-auth-help-btn', 'edit-hook-auth-help-btn'].forEach(id => {
            document.getElementById(id).addEventListener('click', () => this.openAuthHelpDrawer());
        });
        document.getElementById('auth-help-close').addEventListener('click', () => this.closeAuthHelpDrawer());
        document.getElementById('key-lineage-close').addEventListener('click', () => this.closeLineageDrawer());

        // The shared backdrop and Escape close whichever drawer is actually open — at most one of
        // the two is ever visible at a time, so closing "the other one" too is harmless.
        document.getElementById('drawer-backdrop').addEventListener('click', () => {
            this.closeAuthHelpDrawer();
            this.closeLineageDrawer();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('auth-help-drawer').classList.contains('hidden')) this.closeAuthHelpDrawer();
            if (!document.getElementById('key-lineage-drawer').classList.contains('hidden')) this.closeLineageDrawer();
        });

        // Parameters modal
        document.getElementById('form-add-param').addEventListener('submit', (e) => this.addParameter(e));
        document.getElementById('param-cancel-edit-btn').addEventListener('click', () => this.cancelParamEdit());
        document.getElementById('params-modal-close').addEventListener('click', () => {
            document.getElementById('params-modal').classList.add('hidden');
        });

        // JSON payload extractor
        document.getElementById('btn-open-json-extractor').addEventListener('click', () => this.openJsonExtractorModal());
        document.getElementById('json-extractor-parse-btn').addEventListener('click', () => this.parseJsonExtractor());
        document.getElementById('json-extractor-close-x').addEventListener('click', () => {
            document.getElementById('json-extractor-modal').classList.add('hidden');
        });

        // Execution detail modal
        document.getElementById('execution-modal-close').addEventListener('click', () => {
            document.getElementById('execution-modal').classList.add('hidden');
        });

        // Keys
        document.getElementById('form-create-apikey').addEventListener('submit', (e) => this.createApiKey(e));
        document.getElementById('apikey-can-manage-keys').addEventListener('change', () => this.syncApiKeySigningFields());
        document.getElementById('apikey-generate-signing-secret').addEventListener('change', () => this.syncApiKeySigningFields());
        this.syncApiKeySigningFields();
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
        document.getElementById('btn-purge-hooks').addEventListener('click', () => this.purgeDeletedHooksNow());

        // Audit filters — explicit search only, matching the execution history filter's own
        // convention: the button, Enter in a text filter, or either datetime field's own change.
        document.getElementById('audit-search-btn').addEventListener('click', () => this.loadAuditLogs());
        document.getElementById('audit-clear-filters-btn').addEventListener('click', () => this.clearAuditFilters());
        document.getElementById('audit-since-filter').addEventListener('change', () => this.loadAuditLogs());
        document.getElementById('audit-until-filter').addEventListener('change', () => this.loadAuditLogs());
        ['audit-action-filter', 'audit-ip-filter', 'audit-key-filter'].forEach(id => {
            document.getElementById(id).addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.loadAuditLogs();
                }
            });
        });

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

// Mirrors `executor::is_valid_param_key` exactly: the JSON extractor checks this client-side purely
// to grey out a button early, since the server re-validates regardless — this is a UX shortcut, not
// the authority on what a valid key is.
function executorIsValidParamKey(key) {
    return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
}

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    window.app = new HookExecutorClient();
});
