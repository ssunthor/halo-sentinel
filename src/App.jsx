import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, ChevronDown, Clock, Server, RefreshCw, AlertTriangle, X, Globe, CheckCircle, Loader2, ChevronUp, ScrollText, Settings2, BookOpen } from 'lucide-react';
import NetboxVulnerabilities from './components/NetboxVulnerabilities';
import Leaderboard from './components/Leaderboard';
import ChangelogViewer from './components/ChangelogViewer';
import SettingsPage from './components/Settings';
import UserGuide from './components/UserGuide';
import { InfoTip } from './components/Tooltip';

const apiBase = window._env_?.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:5174';


const formatAge = (isoDate) => {
  if (!isoDate) return null;
  const diffH = (Date.now() - new Date(isoDate).getTime()) / 3600000;
  if (diffH < 1) return `${Math.round(diffH * 60)}m ago`;
  if (diffH < 24) return `${Math.round(diffH)}h ago`;
  return `${Math.round(diffH / 24)}d ago`;
};

// ---------------------------------------------------------------------------
// GLOBAL SCAN PANEL
// ---------------------------------------------------------------------------
const fmtSecs = (s) => {
  if (s == null) return '—';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), sec = Math.round(s % 60);
  return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
};

const StatBox = ({ label, value, sub, highlight, tooltip }) => (
  <div className="bg-gray-800 rounded-lg px-3 py-2">
    <div className="flex items-center gap-1 text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">
      {label}
      {tooltip && <InfoTip content={tooltip} position="bottom" size={10} />}
    </div>
    <div className={`font-mono font-bold text-sm ${highlight ? 'text-green-400' : 'text-white'}`}>{value}</div>
    {sub && <div className="text-[10px] text-gray-500 mt-0.5">{sub}</div>}
  </div>
);

const GlobalScanPanel = ({ apiBase }) => {
  const [open, setOpen] = useState(false);
  const [scanState, setScanState] = useState(null);
  const [starting, setStarting] = useState(false);
  const esRef = useRef(null);

  const connectSse = useCallback(() => {
    if (esRef.current) esRef.current.close();
    const es = new EventSource(`${apiBase}/api/scan/global/stream`);
    esRef.current = es;
    es.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.state) setScanState(msg.state);
        if (msg.type === 'complete') { es.close(); esRef.current = null; }
      } catch {}
    };
    es.onerror = () => { es.close(); esRef.current = null; };
  }, [apiBase]);

  useEffect(() => {
    fetch(`${apiBase}/api/scan/global/status`)
      .then(r => r.ok ? r.json() : null)
      .then(s => { if (s) setScanState(s); })
      .catch(() => {});
  }, [apiBase]);

  useEffect(() => {
    if (scanState?.status === 'running' && !esRef.current) {
      connectSse();
      setOpen(true);
    }
  }, [scanState?.status, connectSse]);

  useEffect(() => () => esRef.current?.close(), []);

  const startScan = async () => {
    setStarting(true);
    setOpen(true);
    try {
      await fetch(`${apiBase}/api/scan/global`, { method: 'POST' });
      connectSse();
    } catch (e) {
      console.error('Failed to start global scan:', e);
    } finally {
      setStarting(false);
    }
  };

  const status = scanState?.status || 'idle';
  const isRunning = status === 'running';
  const isDone = status === 'complete' || status === 'error';
  const hasState = isDone || isRunning;

  const nvdPct = scanState?.nvd_total > 0
    ? Math.round((scanState.nvd_queried / scanState.nvd_total) * 100)
    : 0;
  const savePct = scanState?.total_tenants > 0
    ? Math.round((scanState.tenants_saved / scanState.total_tenants) * 100)
    : 0;

  return (
    <div className="relative">
      <button
        onClick={() => hasState ? setOpen(o => !o) : startScan()}
        disabled={starting}
        className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-colors disabled:opacity-60 bg-gray-800 border-gray-700 text-gray-300 hover:bg-green-900/30 hover:border-green-500/40 hover:text-green-400"
      >
        {starting ? <Loader2 size={13} className="animate-spin" />
          : isRunning ? <Loader2 size={13} className="animate-spin text-green-400" />
          : <Globe size={13} />}
        {starting ? 'Starting…' : isRunning ? 'Scanning…' : 'Scan All Tenants'}
        {hasState && <ChevronDown size={11} className={`transition-transform ${open ? 'rotate-180' : ''}`} />}
      </button>

      {open && scanState && (
        <div className="absolute right-0 top-full mt-2 w-[500px] bg-gray-900 border border-gray-700 rounded-xl shadow-2xl z-50 p-4 text-xs max-h-[85vh] overflow-y-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-3">
            <span className="font-bold text-white uppercase tracking-widest text-[10px]">Global Scan Progress</span>
            <div className="flex items-center gap-2">
              {isRunning && <span className="flex items-center gap-1 text-green-400 animate-pulse"><Loader2 size={11} className="animate-spin" /> Running</span>}
              {status === 'complete' && <span className="flex items-center gap-1 text-green-400"><CheckCircle size={11} /> Complete</span>}
              {status === 'error' && <span className="text-red-400">Error</span>}
              <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-white ml-1"><X size={13} /></button>
            </div>
          </div>

          {/* Current phase */}
          <p className="text-green-400/80 italic mb-4 text-[11px]">{scanState.phase || 'Initializing…'}</p>

          {/* ── Inventory ── */}
          <div className="mb-1 text-[10px] font-bold text-gray-600 uppercase tracking-widest">Inventory</div>
          <div className="grid grid-cols-3 gap-2 mb-4">
            <StatBox label="Total devices" value={(scanState.total_devices || scanState.devices_fetched || 0).toLocaleString()}
              tooltip="All physical devices and virtual machines fetched from NetBox across the entire instance, regardless of tenant assignment." />
            <StatBox label="Physical" value={(scanState.physical_devices || 0).toLocaleString()}
              tooltip="Physical network devices from NetBox DCIM — routers, switches, firewalls, servers, and other hardware." />
            <StatBox label="Virtual machines" value={(scanState.virtual_machines || 0).toLocaleString()}
              tooltip="Virtual machines from NetBox Virtualization. Their OS version is read from the os_version custom field rather than os_build." />
          </div>

          {/* ── Platform breakdown ── */}
          <div className="mb-1 text-[10px] font-bold text-gray-600 uppercase tracking-widest">Platform Analysis</div>
          <div className="grid grid-cols-3 gap-2 mb-4">
            <StatBox label="OS platforms" value={(scanState.unique_platforms || 0).toLocaleString()} sub="distinct OS types"
              tooltip="Number of distinct operating system platform names found across all devices (e.g. FortiOS, IOS XE, Ubuntu). Each platform may have multiple firmware versions." />
            <StatBox label="Version combos" value={(scanState.unique_combos || 0).toLocaleString()} sub="unique NVD queries"
              tooltip="Unique platform + version combinations. This equals the number of NVD API calls required — all devices sharing the same platform and version share one query, dramatically reducing API usage." />
            <StatBox label="No platform data" value={(scanState.no_platform_count || 0).toLocaleString()} sub="skipped"
              tooltip="Devices skipped during CVE lookup because NetBox has no platform or OS version configured. These devices may have undetected vulnerabilities and should be updated in NetBox." />
          </div>

          {/* ── NVD queries ── */}
          <div className="mb-1 text-[10px] font-bold text-gray-600 uppercase tracking-widest">NVD Queries</div>
          <div className="grid grid-cols-3 gap-2 mb-2">
            <StatBox label="Completed" value={(scanState.nvd_queried || 0).toLocaleString()} highlight={scanState.nvd_queried > 0}
              tooltip="NVD queries that have received a response, either from a live API call or from the local CVE cache." />
            <StatBox label="Waiting" value={Math.max(0, (scanState.nvd_total || 0) - (scanState.nvd_queried || 0)).toLocaleString()}
              tooltip="NVD queries still in the queue. The broker processes one query every 10 seconds to comply with NIST rate limits." />
            <StatBox label="Cache hits" value={(scanState.nvd_cached || 0).toLocaleString()} sub="no API call needed"
              tooltip="Queries answered instantly from the local CVE cache — no NVD API call was required. Cache is persisted to disk and reused across scans." />
          </div>
          {scanState.nvd_total > 0 && (
            <div className="mb-4">
              <div className="flex justify-between text-[10px] text-gray-500 mb-1">
                <span>NVD progress</span><span>{nvdPct}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                <div className="bg-green-600 h-full transition-all duration-500" style={{ width: `${nvdPct}%` }} />
              </div>
            </div>
          )}

          {/* ── Results ── */}
          <div className="mb-1 text-[10px] font-bold text-gray-600 uppercase tracking-widest">Results</div>
          <div className="grid grid-cols-2 gap-2 mb-4">
            <StatBox label="Devices with CVEs" value={(scanState.devices_with_cves || 0).toLocaleString()} highlight={scanState.devices_with_cves > 0}
              tooltip="Total number of devices across all tenants where at least one CVE was matched by the NVD API. Devices with no platform data are excluded from CVE lookup." />
            <StatBox
              label="Tenants saved"
              value={`${(scanState.tenants_saved || 0).toLocaleString()} / ${(scanState.total_tenants || 0).toLocaleString()}`}
              sub={scanState.total_tenants > 0 ? `${savePct}%` : ''}
              tooltip="Tenant scan results written to the database. Results are saved incrementally — each tenant is persisted as soon as all its devices have been processed, so partial results are available before the scan completes." />
          </div>

          {/* ── Timing ── */}
          <div className="border-t border-gray-800 pt-3 flex flex-wrap gap-x-5 gap-y-1 text-gray-500 text-[11px]">
            <span>Elapsed: <span className="text-gray-300 font-mono">{fmtSecs(scanState.elapsed_seconds)}</span></span>
            {scanState.phase_timings?.inventory_seconds != null && (
              <span>Inventory: <span className="text-gray-300 font-mono">{fmtSecs(scanState.phase_timings.inventory_seconds)}</span></span>
            )}
            {scanState.phase_timings?.nvd_seconds != null && (
              <span>NVD: <span className="text-gray-300 font-mono">{fmtSecs(scanState.phase_timings.nvd_seconds)}</span></span>
            )}
            {scanState.phase_timings?.save_seconds != null && (
              <span>Save: <span className="text-gray-300 font-mono">{fmtSecs(scanState.phase_timings.save_seconds)}</span></span>
            )}
          </div>

          {scanState.error && <p className="mt-2 text-red-400 break-words">{scanState.error}</p>}

          {isDone && (
            <button
              onClick={startScan}
              disabled={starting}
              className="mt-4 w-full py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:border-green-500/40 hover:text-green-400 transition-colors text-xs font-semibold"
            >
              Run Again
            </button>
          )}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// TENANT SELECTOR — server-side search, debounced
// ---------------------------------------------------------------------------
const TenantSelector = ({ selectedTenant, onSelect }) => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [recent, setRecent] = useState([]);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);
  const [devicesOnly, setDevicesOnly] = useState(false);
  const inputRef = useRef(null);
  const ref = useRef(null);
  const debounceRef = useRef(null);

  // Close on outside click
  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
        setQuery('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Load recently-scanned tenants when dropdown opens with no query
  useEffect(() => {
    if (!open || query.trim()) return;
    fetch(`${apiBase}/api/tenants/recent`)
      .then(r => r.ok ? r.json() : [])
      .then(setRecent)
      .catch(() => setRecent([]));
  }, [open, query]);

  // Debounced server-side search
  useEffect(() => {
    clearTimeout(debounceRef.current);
    const q = query.trim();
    if (!q) { setResults([]); setSearchError(null); return; }

    setSearching(true);
    setSearchError(null);
    debounceRef.current = setTimeout(async () => {
      try {
        const url = `${apiBase}/api/tenants/search?q=${encodeURIComponent(q)}&limit=50${devicesOnly ? '&devices_only=true' : ''}`;
        const res = await fetch(url);
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || `HTTP ${res.status}`);
        }
        setResults(await res.json());
      } catch (e) {
        setSearchError(e.message);
        setResults([]);
      } finally {
        setSearching(false);
      }
    }, 300);

    return () => clearTimeout(debounceRef.current);
  }, [query, devicesOnly]);

  const handleSelect = (t) => {
    onSelect(t);
    setQuery('');
    setOpen(false);
  };

  const displayValue = open ? query : (selectedTenant?.name || '');
  const listToShow = query.trim() ? results : recent;

  const TenantRow = ({ t }) => (
    <button
      key={t.id}
      onMouseDown={e => e.preventDefault()}
      onClick={() => handleSelect(t)}
      className={`w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800 transition-colors border-b border-gray-800/60 last:border-0 ${String(t.id) === String(selectedTenant?.id) ? 'bg-gray-800' : ''}`}
    >
      <div className="flex-grow min-w-0">
        <div className="text-sm font-semibold text-white truncate">{t.name}</div>
        {t.description && (
          <div className="text-xs text-gray-500 truncate mt-0.5">{t.description}</div>
        )}
      </div>
      <div className="flex-shrink-0 flex flex-col items-end gap-1">
        {t.device_count > 0 && (
          <span className="flex items-center gap-1 text-xs text-gray-400">
            <Server size={10} />{t.device_count}
          </span>
        )}
        {t.last_scan && (
          <span className={`flex items-center gap-1 text-xs ${t.is_stale ? 'text-yellow-500' : 'text-gray-500'}`}>
            <Clock size={10} />{formatAge(t.last_scan)}
            {t.is_stale && <AlertTriangle size={10} />}
          </span>
        )}
      </div>
    </button>
  );

  return (
    <div className="relative" ref={ref}>
      <div className={`flex items-center gap-2 bg-gray-800 border rounded-lg px-3 py-2 min-w-[280px] transition-colors ${open ? 'border-green-500/50' : 'border-gray-700'}`}>
        <Shield size={14} className="text-green-500 flex-shrink-0" />
        <input
          ref={inputRef}
          type="text"
          value={displayValue}
          placeholder="Search tenants..."
          onFocus={() => setOpen(true)}
          onChange={e => { setQuery(e.target.value); setOpen(true); }}
          onKeyDown={e => {
            if (e.key === 'Escape') { setOpen(false); setQuery(''); inputRef.current?.blur(); }
            if (e.key === 'Enter' && listToShow.length === 1) handleSelect(listToShow[0]);
          }}
          className="flex-grow bg-transparent text-sm text-white placeholder-gray-500 outline-none min-w-0"
          autoComplete="off"
        />
        {searching && <RefreshCw size={12} className="animate-spin text-gray-400 flex-shrink-0" />}
        {!searching && open && query ? (
          <button onMouseDown={e => e.preventDefault()} onClick={() => { setQuery(''); inputRef.current?.focus(); }} className="text-gray-500 hover:text-white flex-shrink-0">
            <X size={13} />
          </button>
        ) : (
          !searching && <ChevronDown size={14} className={`flex-shrink-0 text-gray-400 transition-transform ${open ? 'rotate-180' : ''}`} />
        )}
      </div>

      {open && (
        <div className="absolute top-full right-0 mt-1 w-[380px] bg-gray-900 border border-gray-700 rounded-lg shadow-2xl z-50 overflow-hidden">
          {!query.trim() && recent.length > 0 && (
            <div className="px-3 pt-2 pb-1">
              <span className="text-[10px] font-bold text-gray-600 uppercase tracking-widest">Recently Scanned</span>
            </div>
          )}
          <div className="max-h-80 overflow-y-auto">
            {searchError && (
              <div className="px-4 py-3 text-xs text-red-400">{searchError}</div>
            )}
            {!searchError && listToShow.length === 0 && (
              <div className="px-4 py-3 text-sm text-gray-500">
                {searching ? 'Searching...' : query.trim() ? `No results for "${query}"` : 'Type to search tenants'}
              </div>
            )}
            {!searchError && listToShow.map(t => <TenantRow key={t.id} t={t} />)}
          </div>
          <div className="px-3 py-2 border-t border-gray-800 flex items-center justify-between gap-3">
            <span className="text-[10px] text-gray-600">
              {query.trim()
                ? `Up to 50 results${devicesOnly ? ' · devices filter active' : ''}`
                : `${recent.length} recently scanned · type to search`}
            </span>
            <label
              onMouseDown={e => e.preventDefault()}
              className="flex items-center gap-1.5 cursor-pointer select-none group"
            >
              <div
                onClick={() => setDevicesOnly(v => !v)}
                className={`w-7 h-4 rounded-full transition-colors relative ${devicesOnly ? 'bg-green-600' : 'bg-gray-700'}`}
              >
                <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-transform ${devicesOnly ? 'translate-x-3.5' : 'translate-x-0.5'}`} />
              </div>
              <span className={`text-[10px] font-medium ${devicesOnly ? 'text-green-400' : 'text-gray-500'} group-hover:text-gray-300 transition-colors`}>
                Has devices
              </span>
            </label>
          </div>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// APP SHELL
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// CHANGELOG MODAL
// ---------------------------------------------------------------------------
const ChangelogModal = ({ onClose, apiBase }) => {
  const [versions, setVersions] = useState(null);

  useEffect(() => {
    fetch(`${apiBase}/api/changelog`)
      .then(r => r.ok ? r.json() : [])
      .then(setVersions)
      .catch(() => setVersions([]));
  }, [apiBase]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-gray-950 border border-gray-800 rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2">
            <ScrollText size={15} className="text-green-400" />
            <span className="text-sm font-bold text-white tracking-wide">What's New</span>
            <span className="text-[10px] text-gray-500 uppercase tracking-widest">Defense Halo Customer CVE Analyzer</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>
        {/* Body */}
        <div className="overflow-y-auto flex-grow px-5 py-4">
          {versions === null ? (
            <div className="flex items-center justify-center py-12 gap-2 text-gray-500 text-sm">
              <RefreshCw size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <ChangelogViewer versions={versions} isPopup />
          )}
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// APP SHELL
// ---------------------------------------------------------------------------
export default function App() {
  const [selectedTenant, setSelectedTenant] = useState(null);
  const [showChangelog, setShowChangelog] = useState(false);
  const [page, setPage] = useState('dashboard'); // 'dashboard' | 'settings' | 'guide'

  return (
    <div className="min-h-screen bg-black text-white" style={{ fontFamily: 'monospace' }}>
      {/* NAV BAR */}
      <nav className="sticky top-0 z-40 bg-gray-950 border-b border-gray-800 shadow-lg">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex items-center gap-4">
          <div className="flex items-center gap-3 flex-shrink-0">
            <button
              onClick={() => setPage('dashboard')}
              className="w-8 h-8 rounded-lg bg-green-500/10 border border-green-500/30 flex items-center justify-center hover:bg-green-500/20 transition-colors"
            >
              <Shield size={16} className="text-green-500" />
            </button>
            <div className="hidden sm:block">
              <div className="text-sm font-bold text-white tracking-wide">DEFENSE HALO</div>
              <div className="text-[10px] text-green-500 uppercase tracking-widest font-semibold">Customer CVE Analyzer</div>
            </div>
          </div>

          <div className="flex-grow" />

          <button
            onClick={() => setShowChangelog(true)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs border border-gray-700 bg-gray-900 text-gray-400 hover:text-green-400 hover:border-green-500/40 transition-colors flex-shrink-0"
            title="What's New"
          >
            <ScrollText size={13} />
            <span className="hidden sm:inline">What's New</span>
          </button>

          <button
            onClick={() => setPage(p => p === 'guide' ? 'dashboard' : 'guide')}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs border transition-colors flex-shrink-0 ${
              page === 'guide'
                ? 'border-green-500/50 bg-green-900/20 text-green-400'
                : 'border-gray-700 bg-gray-900 text-gray-400 hover:text-green-400 hover:border-green-500/40'
            }`}
            title="User Guide"
          >
            <BookOpen size={13} />
            <span className="hidden sm:inline">User Guide</span>
          </button>

          {page === 'dashboard' && <GlobalScanPanel apiBase={apiBase} />}

          {page === 'dashboard' && (
            <TenantSelector
              selectedTenant={selectedTenant}
              onSelect={setSelectedTenant}
            />
          )}

          <button
            onClick={() => setPage(p => p === 'settings' ? 'dashboard' : 'settings')}
            title="Settings"
            className={`p-2 rounded-lg border transition-colors flex-shrink-0 ${
              page === 'settings'
                ? 'border-green-500/50 bg-green-900/20 text-green-400'
                : 'border-gray-700 bg-gray-900 text-gray-400 hover:text-green-400 hover:border-green-500/40'
            }`}
          >
            <Settings2 size={15} />
          </button>
        </div>
      </nav>

      {/* MAIN CONTENT */}
      {page === 'settings' ? (
        <SettingsPage />
      ) : page === 'guide' ? (
        <UserGuide />
      ) : (
        <main className="max-w-screen-2xl mx-auto">
          {!selectedTenant ? (
            <Leaderboard apiBase={apiBase} onSelectTenant={setSelectedTenant} />
          ) : (
            <NetboxVulnerabilities
              apiBase={apiBase}
              tenantId={String(selectedTenant.id)}
              tenantName={selectedTenant.name}
            />
          )}
        </main>
      )}

      {/* CHANGELOG MODAL */}
      {showChangelog && (
        <ChangelogModal apiBase={apiBase} onClose={() => setShowChangelog(false)} />
      )}
    </div>
  );
}
