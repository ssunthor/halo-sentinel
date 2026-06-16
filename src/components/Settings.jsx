import React, { useState, useEffect, useCallback } from 'react';
import {
  Bell, Settings2, ChevronLeft, Plus, Trash2, Send,
  CheckCircle, AlertTriangle, RefreshCw, ToggleLeft, ToggleRight,
  Mail, Clock, Server, SlidersHorizontal, Search, X,
} from 'lucide-react';
import TagInput from './TagInput';
import RichEditor from './RichEditor';

const apiBase = window._env_?.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:5174';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const DAYS_OF_WEEK = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
const DAYS_OF_MONTH = Array.from({ length: 31 }, (_, i) => i + 1);

const DEFAULT_CONFIG = {
  enabled: false,
  smtp_host: '', smtp_port: 587, smtp_tls: 'starttls',
  smtp_username: '', smtp_password: '',
  from_address: '',
  to_addresses: [], cc_addresses: [], bcc_addresses: [],
  subject: 'Defense Halo CVE Report — {date}',
  body_preamble: '',
  schedule_frequency: 'daily',
  schedule_time_utc: '00:00',
  schedule_day_of_week: 1,
  schedule_day_of_month: 1,
  filter_tenant_ids: [],
  filter_platforms: [],
};

const scheduleLabel = (cfg) => {
  const time = cfg.schedule_time_utc || '00:00';
  const freq = cfg.schedule_frequency || 'daily';
  if (freq === 'daily')   return `Daily at ${time} UTC`;
  if (freq === 'weekly')  return `Weekly · ${DAYS_OF_WEEK[(cfg.schedule_day_of_week || 1) - 1]} at ${time} UTC`;
  if (freq === 'monthly') return `Monthly · Day ${cfg.schedule_day_of_month || 1} at ${time} UTC`;
  return freq;
};

const Field = ({ label, hint, children, required }) => (
  <div>
    <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
      {label}{required && <span className="text-red-500 ml-0.5">*</span>}
    </label>
    {children}
    {hint && <p className="mt-1 text-[10px] text-gray-600">{hint}</p>}
  </div>
);

const Input = (props) => (
  <input
    {...props}
    className={`w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-green-500/50 transition-colors ${props.className || ''}`}
  />
);

const Select = ({ children, ...props }) => (
  <select
    {...props}
    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-green-500/50 transition-colors"
  >
    {children}
  </select>
);

const StatusBanner = ({ status }) => {
  if (!status) return null;
  const isError = status.type === 'error';
  return (
    <div className={`flex items-start gap-2 px-4 py-3 rounded-lg border text-sm ${
      isError
        ? 'bg-red-900/20 border-red-500/40 text-red-300'
        : 'bg-green-900/20 border-green-500/40 text-green-300'
    }`}>
      {isError
        ? <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
        : <CheckCircle size={15} className="flex-shrink-0 mt-0.5" />
      }
      {status.message}
    </div>
  );
};

// ---------------------------------------------------------------------------
// MultiSelect — searchable checkbox list for tenant/vendor filtering
// ---------------------------------------------------------------------------
function MultiSelect({ options = [], value = [], onChange, placeholder = 'All', emptyMsg = 'No options available' }) {
  const [search, setSearch] = useState('');

  const filtered = options.filter(o =>
    !search || o.label.toLowerCase().includes(search.toLowerCase())
  );

  const toggle = (val) => {
    if (value.includes(val)) onChange(value.filter(v => v !== val));
    else onChange([...value, val]);
  };

  const selectAll  = () => onChange(options.map(o => o.value));
  const clearAll   = () => onChange([]);

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden bg-gray-800/40">
      {/* Summary + bulk actions */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/80 border-b border-gray-700">
        <span className="text-xs text-gray-400 flex-grow">
          {value.length === 0
            ? <span className="text-gray-600">{placeholder}</span>
            : <span className="text-green-400 font-semibold">{value.length} of {options.length} selected</span>
          }
        </span>
        {options.length > 0 && (
          <div className="flex items-center gap-2">
            <button onClick={selectAll} className="text-[10px] text-gray-600 hover:text-white transition-colors">All</button>
            <button onClick={clearAll}  className="text-[10px] text-gray-600 hover:text-white transition-colors">None</button>
          </div>
        )}
      </div>

      {/* Search */}
      <div className="flex items-center gap-1.5 px-2.5 py-1.5 border-b border-gray-700">
        <Search size={11} className="text-gray-600 flex-shrink-0" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter list…"
          className="flex-grow bg-transparent text-xs text-white placeholder-gray-600 focus:outline-none"
        />
        {search && (
          <button onClick={() => setSearch('')} className="text-gray-600 hover:text-white">
            <X size={10} />
          </button>
        )}
      </div>

      {/* Checkbox list */}
      <div className="max-h-44 overflow-y-auto">
        {options.length === 0 ? (
          <p className="px-3 py-5 text-xs text-gray-600 text-center">{emptyMsg}</p>
        ) : filtered.length === 0 ? (
          <p className="px-3 py-5 text-xs text-gray-600 text-center">No matches for "{search}"</p>
        ) : (
          filtered.map(opt => (
            <label
              key={opt.value}
              className="flex items-center gap-2.5 px-3 py-2 hover:bg-gray-700/60 cursor-pointer border-b border-gray-800/60 last:border-0"
            >
              <input
                type="checkbox"
                checked={value.includes(opt.value)}
                onChange={() => toggle(opt.value)}
                className="w-3.5 h-3.5 accent-green-500 flex-shrink-0 rounded"
              />
              <span className="text-xs text-gray-300 flex-grow min-w-0 truncate">{opt.label}</span>
              {opt.sub && <span className="text-[10px] text-gray-600 flex-shrink-0">{opt.sub}</span>}
            </label>
          ))
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Notification edit form
// ---------------------------------------------------------------------------
const NotificationForm = ({ initial, onSave, onBack }) => {
  const [cfg, setCfg]       = useState({ ...DEFAULT_CONFIG, ...initial });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState(null);

  // Filter data
  const [customers, setCustomers] = useState([]);
  const [vendors, setVendors]     = useState([]);
  const [vendorsLoading, setVendorsLoading] = useState(false);

  const set = (key, val) => setCfg(prev => ({ ...prev, [key]: val }));

  // Load all scanned tenants once for the customer filter
  useEffect(() => {
    fetch(`${apiBase}/api/leaderboard?limit=500&min_devices=0`)
      .then(r => r.ok ? r.json() : [])
      .then(data => setCustomers(
        (Array.isArray(data) ? data : []).map(t => ({
          value: t.tenant_id,
          label: t.name,
          sub: `${(t.total_devices || 0).toLocaleString()} devices`,
        }))
      ))
      .catch(() => {});
  }, []);

  // Reload vendor list whenever customer selection changes
  useEffect(() => {
    const ids = cfg.filter_tenant_ids || [];
    const qs = ids.length ? `?tenant_ids=${ids.join(',')}` : '';
    setVendorsLoading(true);
    fetch(`${apiBase}/api/config/vendors${qs}`)
      .then(r => r.ok ? r.json() : [])
      .then(data => {
        const list = Array.isArray(data) ? data : [];
        setVendors(list.map(p => ({ value: p, label: p })));
        // Drop any selected platforms that are no longer in the vendor list
        setCfg(prev => ({
          ...prev,
          filter_platforms: (prev.filter_platforms || []).filter(p => list.includes(p)),
        }));
      })
      .catch(() => {})
      .finally(() => setVendorsLoading(false));
  }, [cfg.filter_tenant_ids]);

  const handleSave = async () => {
    setSaving(true);
    setStatus(null);
    try {
      const isNew = !cfg.id;
      const url   = isNew
        ? `${apiBase}/api/config/notifications`
        : `${apiBase}/api/config/notifications/${cfg.id}`;
      const res = await fetch(url, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const saved = await res.json();
      setCfg(saved);
      setStatus({ type: 'success', message: 'Notification saved successfully.' });
      onSave(saved);
    } catch (e) {
      setStatus({ type: 'error', message: e.message });
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    if (!cfg.id) {
      setStatus({ type: 'error', message: 'Save the notification before sending a test.' });
      return;
    }
    setTesting(true);
    setStatus(null);
    try {
      const res = await fetch(`${apiBase}/api/config/notifications/${cfg.id}/test`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      setStatus({ type: 'success', message: data.message || 'Test email sent.' });
    } catch (e) {
      setStatus({ type: 'error', message: e.message });
    } finally {
      setTesting(false);
    }
  };

  const filterSummary = [];
  if ((cfg.filter_tenant_ids || []).length > 0) filterSummary.push(`${cfg.filter_tenant_ids.length} client${cfg.filter_tenant_ids.length !== 1 ? 's' : ''}`);
  if ((cfg.filter_platforms || []).length > 0)  filterSummary.push(`${cfg.filter_platforms.length} platform${cfg.filter_platforms.length !== 1 ? 's' : ''}`);

  return (
    <div className="max-w-2xl">
      {/* Back + title */}
      <div className="flex items-center gap-3 mb-6">
        <button onClick={onBack} className="text-gray-500 hover:text-white transition-colors">
          <ChevronLeft size={20} />
        </button>
        <div>
          <h2 className="text-base font-bold text-white">
            {cfg.id ? 'Edit Notification' : 'New Notification'}
          </h2>
          <p className="text-xs text-gray-500">Configure schedule, recipients, and message content.</p>
        </div>
      </div>

      <div className="space-y-6">

        {/* ── Identity ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
              <Settings2 size={11} /> Identity
            </div>
            <button
              onClick={() => set('enabled', !cfg.enabled)}
              className="flex items-center gap-1.5 text-xs font-semibold transition-colors"
            >
              {cfg.enabled
                ? <><ToggleRight size={18} className="text-green-400" /><span className="text-green-400">Enabled</span></>
                : <><ToggleLeft  size={18} className="text-gray-600" /><span className="text-gray-500">Disabled</span></>
              }
            </button>
          </div>
          <Field label="Notification Name" required>
            <Input
              value={cfg.name || ''}
              onChange={e => set('name', e.target.value)}
              placeholder="e.g. Daily NOC Report"
            />
          </Field>
        </div>

        {/* ── SMTP ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">
            <Server size={11} /> SMTP Server
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Hostname" required>
              <Input value={cfg.smtp_host} onChange={e => set('smtp_host', e.target.value)} placeholder="mail.example.com" />
            </Field>
            <Field label="Port">
              <Input type="number" value={cfg.smtp_port} onChange={e => set('smtp_port', parseInt(e.target.value) || 587)} />
            </Field>
          </div>
          <Field label="TLS Mode">
            <Select value={cfg.smtp_tls} onChange={e => set('smtp_tls', e.target.value)}>
              <option value="none">None (plaintext)</option>
              <option value="starttls">STARTTLS (port 587)</option>
              <option value="tls">TLS/SSL (port 465)</option>
            </Select>
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Username" hint="Leave blank for unauthenticated relay">
              <Input value={cfg.smtp_username} onChange={e => set('smtp_username', e.target.value)} placeholder="Optional" />
            </Field>
            <Field label="Password">
              <Input type="password" value={cfg.smtp_password} onChange={e => set('smtp_password', e.target.value)} placeholder="Optional" />
            </Field>
          </div>
        </div>

        {/* ── Schedule ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">
            <Clock size={11} /> Schedule
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Frequency">
              <Select value={cfg.schedule_frequency} onChange={e => set('schedule_frequency', e.target.value)}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </Select>
            </Field>
            <Field label="Send Time (UTC)">
              <Input
                type="time"
                value={cfg.schedule_time_utc}
                onChange={e => set('schedule_time_utc', e.target.value)}
              />
            </Field>
          </div>
          {cfg.schedule_frequency === 'weekly' && (
            <Field label="Day of Week">
              <Select value={cfg.schedule_day_of_week} onChange={e => set('schedule_day_of_week', parseInt(e.target.value))}>
                {DAYS_OF_WEEK.map((d, i) => <option key={d} value={i + 1}>{d}</option>)}
              </Select>
            </Field>
          )}
          {cfg.schedule_frequency === 'monthly' && (
            <Field label="Day of Month">
              <Select value={cfg.schedule_day_of_month} onChange={e => set('schedule_day_of_month', parseInt(e.target.value))}>
                {DAYS_OF_MONTH.map(d => <option key={d} value={d}>{d}</option>)}
              </Select>
            </Field>
          )}
          {cfg.last_sent_at && (
            <p className="text-[11px] text-gray-600">Last sent: {new Date(cfg.last_sent_at).toLocaleString()}</p>
          )}
        </div>

        {/* ── Report Filters ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
              <SlidersHorizontal size={11} /> Report Filters
            </div>
            {filterSummary.length > 0 && (
              <span className="text-[10px] font-semibold text-amber-400 bg-amber-900/20 border border-amber-700/40 px-2 py-0.5 rounded">
                {filterSummary.join(' · ')}
              </span>
            )}
          </div>
          <p className="text-[11px] text-gray-600 -mt-1">
            Leave both filters empty to include the full estate in every report.
          </p>

          <Field
            label="Customer Filter"
            hint="Select specific clients to include. Leave unchecked to include all clients."
          >
            <MultiSelect
              options={customers}
              value={cfg.filter_tenant_ids || []}
              onChange={v => set('filter_tenant_ids', v)}
              placeholder="All clients (no filter)"
              emptyMsg="No scanned clients found — run a scan first."
            />
          </Field>

          <Field
            label="Platform / Vendor Filter"
            hint={
              vendorsLoading
                ? 'Loading platforms…'
                : (cfg.filter_tenant_ids || []).length > 0
                  ? `Showing platforms used by the ${cfg.filter_tenant_ids.length} selected client${cfg.filter_tenant_ids.length !== 1 ? 's' : ''}. Leave unchecked to include all platforms.`
                  : 'Showing all platforms across the estate. Leave unchecked to include all.'
            }
          >
            <MultiSelect
              options={vendors}
              value={cfg.filter_platforms || []}
              onChange={v => set('filter_platforms', v)}
              placeholder="All platforms (no filter)"
              emptyMsg={vendorsLoading ? 'Loading…' : 'No platform data found.'}
            />
          </Field>
        </div>

        {/* ── Recipients ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">
            <Mail size={11} /> Recipients
          </div>
          <Field label="From" required>
            <Input value={cfg.from_address} onChange={e => set('from_address', e.target.value)} placeholder="noc@example.com" />
          </Field>
          <Field label="To" required>
            <TagInput value={cfg.to_addresses} onChange={v => set('to_addresses', v)} placeholder="Add recipient…" />
          </Field>
          <Field label="CC">
            <TagInput value={cfg.cc_addresses} onChange={v => set('cc_addresses', v)} placeholder="Add CC…" />
          </Field>
          <Field label="BCC">
            <TagInput value={cfg.bcc_addresses} onChange={v => set('bcc_addresses', v)} placeholder="Add BCC…" />
          </Field>
        </div>

        {/* ── Message ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">
            <Mail size={11} /> Message
          </div>
          <Field
            label="Subject"
            hint="Tokens: {date} {datetime} {total_clients} {vulnerable} {critical} {peak_score}"
          >
            <Input value={cfg.subject} onChange={e => set('subject', e.target.value)} />
          </Field>
          <Field
            label="Body Preamble"
            hint="This rich-text section appears at the top of the email. The estate summary and top-10 client ranking tables are appended automatically below it."
          >
            <RichEditor
              value={cfg.body_preamble}
              onChange={v => set('body_preamble', v)}
              placeholder="Enter introductory message…"
            />
          </Field>
        </div>

        {/* ── Status + actions ── */}
        <StatusBanner status={status} />

        <div className="flex items-center gap-3 pb-8">
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white text-sm font-bold transition-colors"
          >
            {saving ? <RefreshCw size={14} className="animate-spin" /> : <CheckCircle size={14} />}
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={handleTest}
            disabled={testing || !cfg.id}
            title={!cfg.id ? 'Save first to enable test send' : 'Send test email now'}
            className="flex items-center gap-2 px-5 py-2 rounded-lg border border-gray-700 bg-gray-800 hover:border-green-500/40 hover:text-green-400 disabled:opacity-40 text-gray-300 text-sm font-semibold transition-colors"
          >
            {testing ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
            {testing ? 'Sending…' : 'Send Test'}
          </button>
          <button
            onClick={onBack}
            className="ml-auto text-xs text-gray-600 hover:text-gray-400 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Notification list card
// ---------------------------------------------------------------------------
const NotificationCard = ({ cfg, onEdit, onDelete }) => {
  const [confirming, setConfirming] = useState(false);

  const filterParts = [];
  if ((cfg.filter_tenant_ids || []).length > 0) filterParts.push(`${cfg.filter_tenant_ids.length} client${cfg.filter_tenant_ids.length !== 1 ? 's' : ''}`);
  if ((cfg.filter_platforms  || []).length > 0) filterParts.push(`${cfg.filter_platforms.length} platform${cfg.filter_platforms.length !== 1 ? 's' : ''}`);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center gap-4">
      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.enabled ? 'bg-green-400' : 'bg-gray-600'}`} />
      <div className="flex-grow min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-white truncate">{cfg.name || 'Untitled'}</span>
          {!cfg.enabled && (
            <span className="text-[9px] font-bold uppercase tracking-wider text-gray-600 border border-gray-700 rounded px-1 py-0.5">
              Disabled
            </span>
          )}
        </div>
        <div className="text-xs text-gray-500 mt-0.5 flex items-center gap-3 flex-wrap">
          <span><Clock size={10} className="inline mr-1" />{scheduleLabel(cfg)}</span>
          <span><Mail size={10} className="inline mr-1" />{(cfg.to_addresses || []).length} recipient{(cfg.to_addresses || []).length !== 1 ? 's' : ''}</span>
          {filterParts.length > 0 && (
            <span className="text-amber-500">
              <SlidersHorizontal size={9} className="inline mr-1" />{filterParts.join(' · ')}
            </span>
          )}
          {cfg.last_sent_at && (
            <span>Last sent: {new Date(cfg.last_sent_at).toLocaleString()}</span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <button
          onClick={() => onEdit(cfg)}
          className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 transition-colors"
        >
          Edit
        </button>
        {confirming ? (
          <div className="flex items-center gap-1">
            <button
              onClick={() => onDelete(cfg.id)}
              className="px-2 py-1.5 text-xs font-bold rounded-lg bg-red-900/40 border border-red-500/40 text-red-400 hover:bg-red-900/70 transition-colors"
            >
              Confirm
            </button>
            <button
              onClick={() => setConfirming(false)}
              className="px-2 py-1.5 text-xs rounded-lg border border-gray-700 text-gray-500 hover:text-white transition-colors"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-900/20 transition-colors"
          >
            <Trash2 size={14} />
          </button>
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Notifications tab
// ---------------------------------------------------------------------------
const NotificationsTab = () => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading]             = useState(true);
  const [editing, setEditing]             = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/api/config/notifications`);
      if (res.ok) setNotifications(await res.json());
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = useCallback((saved) => {
    setNotifications(prev => {
      const idx = prev.findIndex(n => n.id === saved.id);
      return idx >= 0 ? prev.map(n => n.id === saved.id ? saved : n) : [...prev, saved];
    });
  }, []);

  const handleDelete = useCallback(async (id) => {
    await fetch(`${apiBase}/api/config/notifications/${id}`, { method: 'DELETE' });
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  if (editing !== null) {
    return (
      <NotificationForm
        initial={editing}
        onSave={handleSave}
        onBack={() => setEditing(null)}
      />
    );
  }

  return (
    <div className="max-w-2xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-bold text-white">Email Notifications</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Schedule CVE report emails to different recipient groups.
          </p>
        </div>
        <button
          onClick={() => setEditing({})}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-500 text-white text-xs font-bold transition-colors"
        >
          <Plus size={13} /> New Notification
        </button>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-12 text-gray-600 text-sm">
          <RefreshCw size={14} className="animate-spin" /> Loading…
        </div>
      ) : notifications.length === 0 ? (
        <div className="py-16 flex flex-col items-center gap-3 text-center">
          <Bell size={32} className="text-gray-700" />
          <div>
            <p className="text-sm font-semibold text-gray-400">No notifications configured</p>
            <p className="text-xs text-gray-600 mt-1">Create one to start sending scheduled CVE reports.</p>
          </div>
          <button
            onClick={() => setEditing({})}
            className="mt-2 px-4 py-2 rounded-lg bg-green-600 hover:bg-green-500 text-white text-sm font-bold transition-colors"
          >
            Create First Notification
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {notifications.map(cfg => (
            <NotificationCard
              key={cfg.id}
              cfg={cfg}
              onEdit={setEditing}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main Settings page
// ---------------------------------------------------------------------------
const TABS = [
  { id: 'general',       label: 'General',       icon: Settings2 },
  { id: 'notifications', label: 'Notifications', icon: Bell      },
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('notifications');

  return (
    <div className="max-w-screen-lg mx-auto px-6 py-6">
      {/* Page header */}
      <div className="mb-6">
        <h1 className="text-xl font-black text-white tracking-wide">Settings</h1>
        <p className="text-xs text-gray-500 mt-0.5">Application configuration</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-gray-800 mb-6">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-bold uppercase tracking-wider border-b-2 -mb-px transition-colors ${
              activeTab === id
                ? 'border-green-500 text-green-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'general' && (
        <div className="max-w-2xl text-sm text-gray-500 py-8 text-center">
          <Settings2 size={32} className="mx-auto mb-3 text-gray-700" />
          General settings coming soon.
        </div>
      )}
      {activeTab === 'notifications' && <NotificationsTab />}
    </div>
  );
}
