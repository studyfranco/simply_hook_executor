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

class HookExecutorClient {
    constructor() {
        this.apiKey = localStorage.getItem('simply_hook_executor_key') || '';
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
        const headers = {
            'Content-Type': 'application/json',
            ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
            ...(options.headers || {})
        };

        try {
            const res = await fetch(`${this.apiBase}${endpoint}`, { ...options, headers });

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
        localStorage.removeItem('simply_hook_executor_key');
        this.showLogin();
    }

    async verifyAuth() {
        try {
            this.state.profile = await this.apiFetch('/auth/me');
            this.showDashboard();
            this.enforceRBACUI();
            this.loadInitialData();
        } catch (e) {
            // Interceptor handles logout
        }
    }

    async login(key) {
        this.apiKey = key;
        localStorage.setItem('simply_hook_executor_key', key);
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
    renderHooksTable() {
        const tbody = document.getElementById('hooks-table-body');

        if (this.state.hooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No hooks defined.</td></tr>';
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
                    <td class="text-sm">${h.default_timeout_seconds}s</td>
                    <td class="text-sm">${h.parameters.length}</td>
                    <td><div class="scope-badges">${rights}</div></td>
                    <td>
                        <div class="flex gap-2">
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
        document.getElementById('edit-hook-description').value = h.description || '';
        document.getElementById('edit-hook-modal').classList.remove('hidden');
    }

    async submitEditHook(e) {
        e.preventDefault();
        const id = document.getElementById('edit-hook-id').value;
        const payload = {
            name: document.getElementById('edit-hook-name').value,
            script_path: document.getElementById('edit-hook-script-path').value,
            default_timeout_seconds: parseInt(document.getElementById('edit-hook-timeout').value, 10),
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
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No API keys.</td></tr>';
        } else {
            tbody.innerHTML = this.state.apiKeys.map(k => `
                <tr>
                    <td><input type="checkbox" class="row-select" data-id="${k.id}"></td>
                    <td><strong>${escapeHtml(k.name)}</strong><div class="text-muted text-sm font-mono">${escapeHtml(k.prefix)}...</div></td>
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
            is_master: document.getElementById('apikey-is-master').checked,
            can_manage_keys: document.getElementById('apikey-can-manage-keys').checked,
            can_manage_hooks: document.getElementById('apikey-can-manage-hooks').checked
        };

        try {
            const res = await this.apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('apikey-plaintext').textContent = res.plaintext_key;
            document.getElementById('apikey-created').classList.remove('hidden');
            document.getElementById('form-create-apikey').reset();
            document.getElementById('apikey-max-jobs').value = 10;
            this.loadKeys();
        } catch (err) {}
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
            document.getElementById('secret-reveal-value').textContent = res.plaintext_key;
            document.getElementById('secret-reveal-modal').classList.remove('hidden');
            this.showToast('Secret rotated', 'success');
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
            this.login(document.getElementById('login-key').value);
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
