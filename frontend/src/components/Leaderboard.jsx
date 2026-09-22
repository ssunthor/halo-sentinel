import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, TrendingUp, TrendingDown, Minus, RefreshCw, Download,
  ChevronUp, ChevronDown, Search, X, AlertTriangle, Activity,
  Server, Layers, Bug, Cpu, Zap, Clock, CheckCircle2, DatabaseZap,
  BarChart3, ListTodo, History, ArrowUp, ArrowDown, ExternalLink,
  ShieldAlert, ShieldCheck, ShieldOff,
} from 'lucide-react';
import { InfoTip } from './Tooltip';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const scoreColor = (s) => {
  if (!s || s === 0) return 'text-green-500';
  if (s >= 9) return 'text-red-500';
  if (s >= 7) return 'text-orange-500';
  if (s >= 4) return 'text-yellow-500';
  return 'text-blue-400';
};

const scoreBg = (s) => {
  if (!s || s === 0) return 'bg-green-900/20 border-green-500/30';
  if (s >= 9) return 'bg-red-900/20 border-red-500/30';
  if (s >= 7) return 'bg-orange-900/20 border-orange-500/30';
  if (s >= 4) return 'bg-yellow-900/20 border-yellow-500/30';
  return 'bg-blue-900/20 border-blue-500/30';
};

const postureStyle = (p) => {
  const lp = (p || '').toLowerCase();
  if (lp === 'critical') return 'bg-red-900/30 text-red-400 border-red-500/50';
  if (lp === 'high')     return 'bg-orange-900/30 text-orange-400 border-orange-500/50';
  if (lp === 'medium')   return 'bg-yellow-900/30 text-yellow-400 border-yellow-500/50';
  if (lp === 'low')      return 'bg-blue-900/30 text-blue-400 border-blue-500/50';
  if (lp === 'clean')    return 'bg-green-900/30 text-green-400 border-green-500/50';
  return 'bg-gray-900/30 text-gray-500 border-gray-700';
};

const SEV_CFG = {
  CRITICAL: { bar: 'bg-red-600',    text: 'text-red-400' },
  HIGH:     { bar: 'bg-orange-500', text: 'text-orange-400' },
  MEDIUM:   { bar: 'bg-yellow-500', text: 'text-yellow-400' },
  LOW:      { bar: 'bg-blue-500',   text: 'text-blue-400' },
  UNKNOWN:  { bar: 'bg-gray-600',   text: 'text-gray-400' },
};

const formatAge = (iso) => {
  if (!iso) return '—';
  const h = (Date.now() - new Date(iso).getTime()) / 3600000;
  if (h < 1) return `${Math.round(h * 60)}m ago`;
  if (h < 24) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)}d ago`;
};

const fmtDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const fmt = (n) => (n ?? 0).toLocaleString();

const TrendIcon = ({ trend }) => {
  if (trend === 'improving') return <TrendingDown size={12} className="text-green-400" />;
  if (trend === 'declining') return <TrendingUp size={12} className="text-red-400" />;
  if (trend === 'stable')    return <Minus size={12} className="text-gray-400" />;
  return null;
};

const SortIcon = ({ field, current, dir }) =>
  field === current
    ? dir === 'desc' ? <ChevronDown size={11} /> : <ChevronUp size={11} />
    : <span className="opacity-20"><ChevronDown size={11} /></span>;

// ---------------------------------------------------------------------------
// Delta badge — shown beneath the main value in stat cards
// ---------------------------------------------------------------------------
function DeltaBadge({ delta, goodWhenDown = false, decimals = 0, suffix = '' }) {
  if (delta == null || delta === 0) return <span className="text-gray-700 text-[10px]">no change</span>;
  const isUp = delta > 0;
  const isGood = goodWhenDown ? !isUp : isUp;
  const color = isGood ? 'text-green-400' : 'text-red-400';
  const Icon = isUp ? ArrowUp : ArrowDown;
  const abs = decimals > 0 ? Math.abs(delta).toFixed(decimals) : Math.abs(delta).toLocaleString();
  return (
    <span className={`inline-flex items-center gap-0.5 text-[10px] font-mono font-bold ${color}`}>
      <Icon size={9} />
      {isUp ? '+' : '-'}{abs}{suffix}
    </span>
  );
}

// ---------------------------------------------------------------------------
// FBA status badge — shown in device table rows
// ---------------------------------------------------------------------------
function FbaBadge({ fbaAnalyzed, fbaVulnerable, fbaError }) {
  if (!fbaAnalyzed && !fbaError) return null; // not yet checked
  if (fbaError || !fbaAnalyzed) {
    return <ShieldOff size={12} className="text-gray-700 flex-shrink-0" title="No config data available" />;
  }
  if (fbaVulnerable) {
    return <ShieldAlert size={12} className="text-red-400 flex-shrink-0" title="Config vulnerabilities detected" />;
  }
  return <ShieldCheck size={12} className="text-green-500 flex-shrink-0" title="Config: no issues found" />;
}

// ---------------------------------------------------------------------------
// Drilldown modal — device list for severity / platform / CVE click-through
// ---------------------------------------------------------------------------
function DrilldownModal({ drilldown, onClose, apiBase }) {
  const [data, setData]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState('');

  const mode = drilldown?.type === 'clients' ? 'clients'
             : drilldown?.type === 'cve_instances' ? 'cve_instances'
             : 'devices';

  useEffect(() => {
    if (!drilldown) return;
    setLoading(true);
    setSearch('');
    const qs = drilldown.value
      ? `type=${encodeURIComponent(drilldown.type)}&value=${encodeURIComponent(drilldown.value)}`
      : `type=${encodeURIComponent(drilldown.type)}`;
    fetch(`${apiBase}/api/drilldown?${qs}`)
      .then(r => r.ok ? r.json() : [])
      .then(d => setData(Array.isArray(d) ? d : []))
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  }, [drilldown, apiBase]);

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!drilldown) return null;

  const q = search.toLowerCase();
  const filtered = data.filter(d => {
    if (!q) return true;
    if (mode === 'clients') {
      return (d.name || '').toLowerCase().includes(q);
    }
    if (mode === 'cve_instances') {
      return (d.tenant_name || '').toLowerCase().includes(q)
        || (d.resource_name || '').toLowerCase().includes(q)
        || (d.cve_id || '').toLowerCase().includes(q)
        || (d.platform_name || '').toLowerCase().includes(q);
    }
    return (d.tenant_name || '').toLowerCase().includes(q)
      || (d.resource_name || '').toLowerCase().includes(q)
      || (d.platform_name || '').toLowerCase().includes(q)
      || (d.serial || '').toLowerCase().includes(q)
      || (d.pon || '').toLowerCase().includes(q);
  });

  // Group devices by tenant (only for device-mode tables)
  const tenantGroups = [];
  if (mode === 'devices') {
    let cur = null;
    for (const d of filtered) {
      if (d.tenant_name !== cur) {
        cur = d.tenant_name;
        tenantGroups.push({ name: cur, devices: [] });
      }
      tenantGroups[tenantGroups.length - 1].devices.push(d);
    }
  }

  const exportQs = drilldown.value
    ? `type=${encodeURIComponent(drilldown.type)}&value=${encodeURIComponent(drilldown.value)}`
    : `type=${encodeURIComponent(drilldown.type)}`;
  const exportUrl = `${apiBase}/api/export/drilldown?${exportQs}`;

  const subtitle = loading ? 'Loading…'
    : mode === 'clients' ? `${filtered.length} client${filtered.length !== 1 ? 's' : ''}`
    : mode === 'cve_instances' ? `${filtered.length} CVE instance${filtered.length !== 1 ? 's' : ''}`
    : `${filtered.length} device${filtered.length !== 1 ? 's' : ''} across ${tenantGroups.length} client${tenantGroups.length !== 1 ? 's' : ''}`;

  const placeholder = mode === 'clients' ? 'Search clients…'
    : mode === 'cve_instances' ? 'Search by CVE ID, device, tenant, platform…'
    : 'Filter by tenant, device, platform, serial…';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />
      <div
        className="relative bg-gray-950 border border-gray-800 rounded-2xl shadow-2xl w-[95vw] max-w-6xl max-h-[85vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 flex-shrink-0">
          <div>
            <h2 className="text-base font-bold text-white">{drilldown.label}</h2>
            <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>
          </div>
          <div className="flex items-center gap-3">
            <a href={exportUrl} download className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-500 text-white text-xs font-bold transition-colors">
              <Download size={12} /> Export XLS
            </a>
            <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors p-1"><X size={18} /></button>
          </div>
        </div>

        {/* Search */}
        <div className="px-6 py-2 border-b border-gray-800/60 flex-shrink-0">
          <div className="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5">
            <Search size={12} className="text-gray-600" />
            <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder={placeholder}
              className="flex-grow bg-transparent text-xs text-white placeholder-gray-600 focus:outline-none" />
            {search && <button onClick={() => setSearch('')} className="text-gray-600 hover:text-white"><X size={11} /></button>}
          </div>
        </div>

        {/* Table body */}
        <div className="flex-grow overflow-y-auto px-6 py-3">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-gray-500 text-sm">
              <RefreshCw size={14} className="animate-spin mr-2" /> Loading…
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-gray-600 text-sm">No results found.</div>
          ) : mode === 'clients' ? (
            /* ── Clients table ── */
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-950 z-10">
                <tr className="border-b border-gray-800">
                  {['Client','Devices','Vulnerable','Vuln %','CVE Score','Risk','Trend','Last Scan'].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-[10px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((c, i) => (
                  <tr key={i} className="border-b border-gray-800/40 hover:bg-gray-900/60 transition-colors">
                    <td className="py-2 px-2 font-semibold text-white">{c.name}</td>
                    <td className="py-2 px-2 text-gray-300 font-mono">{fmt(c.total_devices)}</td>
                    <td className={`py-2 px-2 font-mono font-bold ${c.vulnerable_devices > 0 ? 'text-orange-400' : 'text-green-500'}`}>{fmt(c.vulnerable_devices)}</td>
                    <td className="py-2 px-2 text-gray-400 font-mono">{c.vuln_pct ?? 0}%</td>
                    <td className={`py-2 px-2 font-mono font-bold ${scoreColor(c.max_score)}`}>{(c.max_score || 0).toFixed(1)}</td>
                    <td className="py-2 px-2">{c.risk_posture ? <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase ${postureStyle(c.risk_posture)}`}>{c.risk_posture}</span> : <span className="text-gray-700">—</span>}</td>
                    <td className="py-2 px-2"><TrendIcon trend={c.trend} /></td>
                    <td className="py-2 px-2 text-gray-600">{formatAge(c.scanned_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : mode === 'cve_instances' ? (
            /* ── CVE instances table ── */
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-950 z-10">
                <tr className="border-b border-gray-800">
                  {['Client','Device','Platform','Current FW','NVD Min Fix','Eng Rec','CVE ID','Score','Severity','Description'].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-[10px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((c, i) => (
                  <tr key={i} className="border-b border-gray-800/40 hover:bg-gray-900/60 transition-colors">
                    <td className="py-2 px-2 text-white whitespace-nowrap">{c.tenant_name}</td>
                    <td className="py-2 px-2 text-gray-300 truncate max-w-[150px]" title={c.resource_name}>{c.resource_name || '—'}</td>
                    <td className="py-2 px-2 text-gray-400 whitespace-nowrap">{c.platform_name || '—'}</td>
                    <td className="py-2 px-2 text-gray-400 font-mono">{c.current_firmware || '—'}</td>
                    <td className="py-2 px-2 text-amber-400 font-mono">{c.recommended_version || '—'}</td>
                    <td className="py-2 px-2 text-blue-400 font-mono">{c.gia_recommended_version || '—'}</td>
                    <td className="py-2 px-2">
                      <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noopener noreferrer"
                        className="text-blue-400 hover:underline font-mono font-bold" onClick={e => e.stopPropagation()}>
                        {c.cve_id}
                      </a>
                    </td>
                    <td className={`py-2 px-2 font-mono font-bold ${scoreColor(c.score)}`}>{(c.score || 0).toFixed(1)}</td>
                    <td className="py-2 px-2">
                      {c.severity ? <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase ${postureStyle(c.severity)}`}>{c.severity}</span> : '—'}
                    </td>
                    <td className="py-2 px-2 text-gray-500 truncate max-w-[250px]" title={c.description}>{c.description || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            /* ── Devices table (default) ── */
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-950 z-10">
                <tr className="border-b border-gray-800">
                  {['Client','Device Name','Platform','Current FW','NVD Min Fix','Eng Rec','CVE Score','CVEs','Config','Serial','PON'].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-[10px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tenantGroups.map((group) =>
                  group.devices.map((d, di) => (
                    <tr key={`${group.name}-${di}`} className="border-b border-gray-800/40 hover:bg-gray-900/60 transition-colors">
                      {di === 0 ? (
                        <td className="py-2 px-2 font-semibold text-white align-top whitespace-nowrap" rowSpan={group.devices.length}>
                          {group.name}
                          <span className="text-[10px] text-gray-600 font-normal ml-1.5">({group.devices.length})</span>
                        </td>
                      ) : null}
                      <td className="py-2 px-2 text-gray-300 truncate max-w-[180px]" title={d.resource_name}>{d.resource_name || '—'}</td>
                      <td className="py-2 px-2 text-gray-400 whitespace-nowrap">{d.platform_name || '—'}</td>
                      <td className="py-2 px-2 text-gray-400 font-mono">{d.current_firmware || d.os_version || '—'}</td>
                      <td className="py-2 px-2 text-amber-400 font-mono">{d.recommended_version || '—'}</td>
                      <td className="py-2 px-2 text-blue-400 font-mono">{d.gia_recommended_version || '—'}</td>
                      <td className={`py-2 px-2 font-mono font-bold ${scoreColor(d.cve_score)}`}>{(d.cve_score || 0).toFixed(1)}</td>
                      <td className="py-2 px-2 text-gray-400 text-center">{d.cve_count || 0}</td>
                      <td className="py-2 px-2 text-center">
                        <FbaBadge fbaAnalyzed={d.fba_analyzed} fbaVulnerable={d.fba_vulnerable} fbaError={d.fba_error} />
                      </td>
                      <td className="py-2 px-2 text-gray-500 font-mono">{d.serial || '—'}</td>
                      <td className="py-2 px-2 text-gray-500 font-mono">{d.pon || '—'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-panels
// ---------------------------------------------------------------------------
const StatCard = ({ label, value, sub, icon: Icon, accent = 'text-white', tooltip, delta, deltaGoodWhenDown, deltaSuffix, deltaDecimals, onClick }) => (
  <div
    className={`bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-col gap-1 ${onClick ? 'cursor-pointer hover:border-gray-600 hover:bg-gray-800/60 transition-colors' : ''}`}
    onClick={onClick}
  >
    <div className="flex items-center gap-1.5 text-gray-500 text-xs uppercase tracking-wider font-semibold">
      {Icon && <Icon size={12} />}{label}
      {tooltip && <InfoTip content={tooltip} position="bottom" size={10} />}
    </div>
    <div className={`text-2xl font-black font-mono ${accent}`}>{value}</div>
    <div className="flex items-center gap-2 min-h-[16px]">
      {sub && <div className="text-xs text-gray-600">{sub}</div>}
      {delta != null && (
        <DeltaBadge delta={delta} goodWhenDown={deltaGoodWhenDown} suffix={deltaSuffix} decimals={deltaDecimals} />
      )}
    </div>
  </div>
);

const SeverityPanel = ({ breakdown, onDrilldown }) => {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const total = Object.values(breakdown || {}).reduce((s, v) => s + v, 0);
  if (!total) return null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
        <AlertTriangle size={10} /> Severity Breakdown
        <InfoTip content="Breakdown of all CVE instances across every scanned tenant by CVSS severity band. CRITICAL = 9.0–10.0, HIGH = 7.0–8.9, MEDIUM = 4.0–6.9, LOW = 0.1–3.9. One device with multiple CVEs contributes one count per CVE. Click a severity band to view all affected devices." position="bottom" />
      </div>
      <div className="space-y-2">
        {order.map(sev => {
          const count = breakdown[sev] || 0;
          if (!count) return null;
          const pct = Math.round((count / total) * 100);
          const cfg = SEV_CFG[sev] || SEV_CFG.UNKNOWN;
          return (
            <div
              key={sev}
              className="cursor-pointer hover:bg-gray-800/60 rounded-lg px-1.5 py-1 -mx-1.5 transition-colors"
              onClick={() => onDrilldown?.({ type: 'severity', value: sev, label: `${sev} Severity Devices` })}
            >
              <div className="flex justify-between text-xs mb-1">
                <span className={`font-semibold ${cfg.text}`}>{sev}</span>
                <span className="text-gray-400 font-mono">{fmt(count)} <span className="text-gray-600">({pct}%)</span></span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                <div className={`${cfg.bar} h-full rounded-full transition-all duration-700`} style={{ width: `${pct}%` }} />
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-3 pt-3 border-t border-gray-800 text-xs text-gray-600 font-mono">
        {fmt(total)} total CVE instances
      </div>
    </div>
  );
};

const PlatformPanel = ({ platforms, onDrilldown }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
      <Layers size={10} /> Top Platforms by Exposure
      <InfoTip content="OS/firmware platforms ranked by number of vulnerable devices. The progress bar shows what percentage of that platform's devices have at least one CVE. Click a platform to view all affected devices." position="bottom" />
    </div>
    <div className="space-y-2">
      {(platforms || []).slice(0, 8).map((p, i) => (
        <div
          key={i}
          className="flex items-center gap-2 cursor-pointer hover:bg-gray-800/60 rounded-lg px-1.5 py-1 -mx-1.5 transition-colors"
          onClick={() => onDrilldown?.({ type: 'platform', value: p.platform, label: `${p.platform} — Vulnerable Devices` })}
        >
          <span className="text-gray-700 font-mono text-[10px] w-4 text-right">{i + 1}</span>
          <div className="flex-grow min-w-0">
            <div className="flex justify-between items-center mb-0.5">
              <span className="text-xs font-semibold text-white truncate max-w-[140px]">{p.platform}</span>
              <span className={`text-xs font-mono font-bold ${scoreColor(p.max_score)}`}>
                {(p.max_score || 0).toFixed(1)}
              </span>
            </div>
            <div className="flex items-center gap-1">
              <div className="flex-grow bg-gray-800 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-orange-500/70 h-full rounded-full"
                  style={{ width: `${Math.min(p.vuln_pct || 0, 100)}%` }}
                />
              </div>
              <span className="text-[10px] text-gray-500 w-16 text-right flex-shrink-0">
                {fmt(p.vulnerable_devices)}/{fmt(p.total_devices)} ({p.vuln_pct ?? 0}%)
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  </div>
);

const TopCvesPanel = ({ cves, onDrilldown }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
      <Bug size={10} /> Most Widespread CVEs
      <InfoTip content="CVEs that appear on the most devices across the entire estate, sorted by device count. Click any row to view all affected devices. Click the CVE ID link to open its full NVD detail page." position="bottom" />
    </div>
    <div className="space-y-1.5">
      {(cves || []).slice(0, 8).map((c, i) => (
        <div
          key={i}
          className="flex items-start gap-2 group cursor-pointer hover:bg-gray-800/60 rounded-lg px-1.5 py-1 -mx-1.5 transition-colors"
          onClick={() => onDrilldown?.({ type: 'cve', value: c.cve_id, label: `${c.cve_id} — Affected Devices` })}
        >
          <span className="text-gray-700 font-mono text-[10px] w-4 text-right flex-shrink-0 mt-0.5">{i + 1}</span>
          <div className="flex-grow min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:underline font-mono text-[11px] font-bold flex-shrink-0"
                onClick={e => e.stopPropagation()}
              >
                {c.cve_id}
              </a>
              <span className={`text-[10px] font-bold flex-shrink-0 ${scoreColor(c.score)}`}>
                {(c.score || 0).toFixed(1)}
              </span>
              <span className="text-[10px] text-gray-600 flex-shrink-0">
                {fmt(c.device_count)} devices · {fmt(c.tenant_count)} clients
              </span>
            </div>
            <p className="text-[10px] text-gray-500 truncate" title={c.description}>{c.description}</p>
          </div>
        </div>
      ))}
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Scan Trends Panel
// ---------------------------------------------------------------------------
function ScanTrendsPanel({ trends }) {
  const { current, previous, deltas } = trends || {};

  const TrendRow = ({ label, curr, delta, goodWhenDown = false, decimals = 0, accent, suffix = '' }) => (
    <div className="flex items-center justify-between py-1.5 border-b border-gray-800/40 last:border-0">
      <span className="text-xs text-gray-400">{label}</span>
      <div className="flex items-center gap-2.5">
        <span className={`font-mono text-sm font-bold ${accent || 'text-white'}`}>
          {decimals > 0 ? (curr || 0).toFixed(decimals) : fmt(curr || 0)}{suffix}
        </span>
        <div className="w-12 flex justify-end">
          {previous ? (
            <DeltaBadge delta={delta} goodWhenDown={goodWhenDown} decimals={decimals} suffix={suffix} />
          ) : (
            <span className="text-gray-700 text-[10px]">—</span>
          )}
        </div>
      </div>
    </div>
  );

  const SectionLabel = ({ children }) => (
    <div className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold mt-3 mb-1 pt-2 border-t border-gray-800/40 first:border-0 first:mt-0 first:pt-0">
      {children}
    </div>
  );

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest flex items-center gap-1.5">
          <TrendingUp size={10} className="text-green-400" /> Scan Comparison
          <InfoTip content="Comparison of the current scan vs the previous scan. Arrows indicate direction of change. Green = improvement, Red = decline (context-sensitive: more devices is good, more CVEs is bad)." position="bottom" />
        </div>
        {previous && (
          <span className="text-[10px] text-gray-600 font-mono">vs {formatAge(previous.scanned_at)}</span>
        )}
      </div>

      {!current ? (
        <p className="text-xs text-gray-600 py-4 text-center">No scan data yet.</p>
      ) : !previous ? (
        <p className="text-xs text-gray-600 py-4 text-center">Run a second scan to see trends.</p>
      ) : (
        <>
          <SectionLabel>Inventory</SectionLabel>
          <TrendRow label="Total Devices"    curr={current.total_devices}    delta={deltas?.total_devices} />
          <TrendRow label="Physical Devices" curr={current.physical_devices}  delta={deltas?.physical_devices} />
          <TrendRow label="Virtual Machines" curr={current.virtual_machines}  delta={deltas?.virtual_machines} />

          <SectionLabel>Exposure</SectionLabel>
          <TrendRow label="Vulnerable Devices" curr={current.vulnerable_devices} delta={deltas?.vulnerable_devices} goodWhenDown accent={current.vulnerable_devices > 0 ? 'text-orange-400' : 'text-green-400'} />
          <TrendRow label="Critical Devices"   curr={current.critical_devices}   delta={deltas?.critical_devices}   goodWhenDown accent={current.critical_devices > 0 ? 'text-red-400' : 'text-green-400'} />
          <TrendRow label="High Devices"       curr={current.high_devices}       delta={deltas?.high_devices}       goodWhenDown accent={current.high_devices > 0 ? 'text-orange-400' : 'text-green-400'} />
          <TrendRow label="Total CVEs"         curr={current.total_cves}         delta={deltas?.total_cves}         goodWhenDown accent="text-yellow-400" />
          <TrendRow label="Peak Score"         curr={current.peak_score}         delta={deltas?.peak_score}         goodWhenDown decimals={1} accent={scoreColor(current.peak_score)} />

          <SectionLabel>NVD Query Efficiency</SectionLabel>
          <TrendRow label="Cache Hits"  curr={current.nvd_cached}  delta={deltas?.nvd_cached}  accent="text-blue-400" />
          <TrendRow label="API Calls"   curr={current.nvd_queried} delta={deltas?.nvd_queried} goodWhenDown />
          <TrendRow label="Unique Combos" curr={current.nvd_total} delta={deltas?.nvd_total} />
          {current.duration_seconds != null && (
            <TrendRow label="Scan Duration" curr={Math.round(current.duration_seconds)} delta={deltas?.duration_seconds ? Math.round(deltas.duration_seconds) : 0} goodWhenDown suffix="s" />
          )}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan History Panel (collapsible table)
// ---------------------------------------------------------------------------
function ScanHistoryPanel({ apiBase }) {
  const [history, setHistory] = useState([]);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    fetch(`${apiBase}/api/scan-history?limit=10`)
      .then(r => r.ok ? r.json() : [])
      .then(data => setHistory(Array.isArray(data) ? data : []))
      .catch(() => {});
  }, [apiBase]);

  if (history.length === 0) return null;

  const Th = ({ children, right }) => (
    <th className={`px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500 ${right ? 'text-right' : 'text-left'} border-b border-gray-800`}>
      {children}
    </th>
  );
  const Td = ({ children, accent, mono, right }) => (
    <td className={`px-3 py-2 text-xs border-b border-gray-800/50 ${right ? 'text-right' : ''} ${mono ? 'font-mono' : ''} ${accent || 'text-gray-400'}`}>
      {children}
    </td>
  );

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-2">
          <History size={12} className="text-green-400" />
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
            Scan History — {history.length} record{history.length !== 1 ? 's' : ''}
          </span>
        </div>
        {expanded ? <ChevronUp size={13} className="text-gray-600" /> : <ChevronDown size={13} className="text-gray-600" />}
      </button>

      {expanded && (
        <div className="overflow-x-auto border-t border-gray-800">
          <table className="w-full">
            <thead className="bg-gray-900/80">
              <tr>
                <Th>Date / Time</Th>
                <Th right>Devices</Th>
                <Th right>Physical</Th>
                <Th right>VMs</Th>
                <Th right>Vulnerable</Th>
                <Th right>Critical</Th>
                <Th right>High</Th>
                <Th right>CVEs</Th>
                <Th right>Peak</Th>
                <Th right>NVD Hits</Th>
                <Th right>NVD Calls</Th>
                <Th right>Duration</Th>
              </tr>
            </thead>
            <tbody>
              {history.map((row, i) => (
                <tr key={row.id} className={i % 2 === 0 ? 'bg-gray-950/40' : ''}>
                  <Td mono>{fmtDate(row.scanned_at)}</Td>
                  <Td mono right>{fmt(row.total_devices)}</Td>
                  <Td mono right>{fmt(row.physical_devices)}</Td>
                  <Td mono right>{fmt(row.virtual_machines)}</Td>
                  <Td mono right accent={row.vulnerable_devices > 0 ? 'text-orange-400' : 'text-green-500'}>{fmt(row.vulnerable_devices)}</Td>
                  <Td mono right accent={row.critical_devices > 0 ? 'text-red-400' : 'text-gray-600'}>{fmt(row.critical_devices)}</Td>
                  <Td mono right accent={row.high_devices > 0 ? 'text-orange-400' : 'text-gray-600'}>{fmt(row.high_devices)}</Td>
                  <Td mono right accent="text-yellow-400">{fmt(row.total_cves)}</Td>
                  <Td mono right accent={scoreColor(row.peak_score)}>{(row.peak_score || 0).toFixed(1)}</Td>
                  <Td mono right accent="text-blue-400">{fmt(row.nvd_cached)}</Td>
                  <Td mono right>{fmt(row.nvd_queried)}</Td>
                  <Td mono right>{row.duration_seconds != null ? `${Math.round(row.duration_seconds)}s` : '—'}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AI Worker Stats panel
// ---------------------------------------------------------------------------
const STATUS_CFG = {
  starting:  { dot: 'bg-yellow-400 animate-pulse', label: 'Starting',  text: 'text-yellow-400' },
  idle:      { dot: 'bg-gray-500',                 label: 'Idle',       text: 'text-gray-400'   },
  analyzing: { dot: 'bg-green-400 animate-pulse',  label: 'Analyzing',  text: 'text-green-400'  },
  error:     { dot: 'bg-red-500',                  label: 'Error',      text: 'text-red-400'    },
};

const fmtMs = (ms) => {
  if (ms == null) return '—';
  if (ms >= 60000) return `${(ms / 60000).toFixed(1)}m`;
  if (ms >= 1000)  return `${(ms / 1000).toFixed(1)}s`;
  return `${ms}ms`;
};

const MiniStat = ({ icon: Icon, label, value, accent = 'text-white', tooltip }) => (
  <div className="flex flex-col gap-0.5">
    <div className="flex items-center gap-1 text-[10px] text-gray-500 uppercase tracking-wider">
      {Icon && <Icon size={9} />}{label}
      {tooltip && <InfoTip content={tooltip} position="bottom" size={9} />}
    </div>
    <div className={`font-mono font-bold text-sm ${accent}`}>{value ?? '—'}</div>
  </div>
);

const AiStatsPanel = ({ apiBase }) => {
  const [ai, setAi] = useState(null);

  useEffect(() => {
    let cancel = false;
    const poll = async () => {
      try {
        const r = await fetch(`${apiBase}/api/ai/stats`);
        if (r.ok && !cancel) setAi(await r.json());
      } catch {}
    };
    poll();
    const t = setInterval(poll, 5000);
    return () => { cancel = true; clearInterval(t); };
  }, [apiBase]);

  if (!ai) return null;

  const cfg = STATUS_CFG[ai.status] || STATUS_CFG.idle;
  const totalCalls = ai.total_llm_calls || 0;
  const cacheRate  = ai.cache_hit_rate_pct;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Cpu size={13} className="text-purple-400" />
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">AI Analysis Engine</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
          <span className={`text-xs font-semibold ${cfg.text}`}>{cfg.label}</span>
        </div>
      </div>

      {/* Current job */}
      {ai.status === 'analyzing' && (
        <div className="mb-4 bg-purple-900/20 border border-purple-500/30 rounded-lg px-3 py-2 text-xs">
          <div className="text-purple-300 font-semibold truncate">
            {ai.current_device && ai.current_device !== '(estate summary)'
              ? <>Analyzing <span className="font-mono">{ai.current_device}</span></>
              : ai.current_device === '(estate summary)'
              ? 'Generating estate summary…'
              : 'Processing…'}
          </div>
          {ai.current_tenant && (
            <div className="text-purple-500 text-[10px] mt-0.5 truncate">{ai.current_tenant}</div>
          )}
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-x-4 gap-y-3 mb-4">
        <MiniStat icon={BarChart3}  label="Analyzed (24h)"   value={(ai.analyzed_last_24h ?? 0).toLocaleString()} accent="text-green-400"
          tooltip="Devices the AI worker has completed a security assessment for in the last 24 hours. Resets on a rolling basis, not at midnight." />
        <MiniStat icon={ListTodo}   label="In queue"          value={(ai.pending_devices ?? 0).toLocaleString()}   accent={ai.pending_devices > 0 ? 'text-yellow-400' : 'text-gray-400'}
          tooltip="Vulnerable devices across all tenants that still need an AI-generated security assessment. The worker processes these in background, rate-limited to avoid overloading the vLLM endpoint." />
        <MiniStat icon={Server}     label="Tenants pending"   value={(ai.pending_tenants ?? 0).toLocaleString()}
          tooltip="Number of tenants that need either a new estate-level risk summary or have individual devices awaiting AI analysis." />
        <MiniStat icon={Activity}   label="Session total"     value={(ai.total_analyzed ?? 0).toLocaleString()}    accent="text-purple-400"
          tooltip="Total devices analyzed by the AI worker since the backend service last started. Resets on service restart." />
        <MiniStat icon={Zap}        label="API calls"         value={(ai.total_api_calls ?? 0).toLocaleString()}
          tooltip="Actual requests sent to the vLLM inference endpoint this session. Lower is better — the cache avoids redundant calls for identical device profiles." />
        <MiniStat icon={DatabaseZap} label="Cache hits"       value={(ai.total_cache_hits ?? 0).toLocaleString()}  accent="text-blue-400"
          tooltip="Times an analysis result was served from the local LLM response cache instead of making a new API call. Reduces latency and API load for devices with identical configurations." />
      </div>

      {/* Latency row */}
      <div className="border-t border-gray-800 pt-3 grid grid-cols-4 gap-2">
        <MiniStat icon={Clock} label="Avg latency"  value={fmtMs(ai.avg_latency_ms)}  accent="text-cyan-400"
          tooltip="Average response time for real vLLM API calls, measured over the last 100 requests. Does not include cache hits." />
        <MiniStat label="P95"      value={fmtMs(ai.p95_latency_ms)}
          tooltip="95th percentile latency — 95% of API calls complete faster than this value. High P95 vs average indicates occasional slow responses from the vLLM endpoint." />
        <MiniStat label="Min"      value={fmtMs(ai.min_latency_ms)} accent="text-green-400"
          tooltip="Fastest API response recorded in the current latency window (last 100 calls)." />
        <MiniStat label="Max"      value={fmtMs(ai.max_latency_ms)} accent={ai.max_latency_ms > 30000 ? 'text-red-400' : 'text-gray-300'}
          tooltip="Slowest API response recorded in the current latency window. Values over 30s (shown in red) may indicate vLLM endpoint pressure or large context." />
      </div>

      {/* Cache rate bar */}
      {totalCalls > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-800">
          <div className="flex justify-between text-[10px] text-gray-500 mb-1">
            <span>Cache hit rate</span>
            <span className="text-blue-400 font-mono">{cacheRate ?? 0}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-1.5 overflow-hidden">
            <div className="bg-blue-500 h-full rounded-full transition-all duration-700" style={{ width: `${cacheRate ?? 0}%` }} />
          </div>
          <div className="flex justify-between text-[10px] text-gray-700 mt-1">
            <span>{(ai.total_cache_hits ?? 0).toLocaleString()} cached</span>
            <span>{(ai.total_api_calls ?? 0).toLocaleString()} API calls</span>
          </div>
        </div>
      )}

      {ai.total_errors > 0 && (
        <div className="mt-2 text-[10px] text-red-400 flex items-center gap-1">
          <AlertTriangle size={9} /> {ai.total_errors} error(s) this session
        </div>
      )}
    </div>
  );
};


// ---------------------------------------------------------------------------
// Leaderboard table
// ---------------------------------------------------------------------------
const RankBadge = ({ rank }) => {
  if (rank === 1) return <span className="font-bold text-yellow-400 font-mono">🥇</span>;
  if (rank === 2) return <span className="font-bold text-gray-300 font-mono">🥈</span>;
  if (rank === 3) return <span className="font-bold text-orange-500 font-mono">🥉</span>;
  return <span className="text-gray-700 font-mono text-xs w-5 text-right">{rank}</span>;
};

const ThBtn = ({ children, field, current, dir, onSort }) => (
  <button
    onClick={() => onSort(field)}
    className="flex items-center gap-1 hover:text-white transition-colors"
  >
    {children}<SortIcon field={field} current={current} dir={dir} />
  </button>
);

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function Leaderboard({ apiBase, onSelectTenant }) {
  const [stats, setStats] = useState(null);
  const [rows, setRows] = useState([]);
  const [trends, setTrends] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortBy, setSortBy] = useState('max_score');
  const [sortDir, setSortDir] = useState('desc');
  const [filter, setFilter] = useState('');
  const [drilldown, setDrilldown] = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [sRes, lRes, tRes] = await Promise.all([
        fetch(`${apiBase}/api/stats`),
        fetch(`${apiBase}/api/leaderboard?limit=500`),
        fetch(`${apiBase}/api/scan-trends`),
      ]);
      if (!sRes.ok || !lRes.ok) throw new Error('API error');
      const [sData, lData] = await Promise.all([sRes.json(), lRes.json()]);
      setStats(sData);
      setRows(lData);
      if (tRes.ok) setTrends(await tRes.json());
      setError(null);
    } catch (e) {
      setError('Could not load leaderboard data. Make sure the backend is running.');
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 60000);
    return () => clearInterval(t);
  }, [fetchAll]);

  const handleSort = (field) => {
    setSortBy(prev => {
      if (prev === field) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
      else setSortDir('desc');
      return field;
    });
  };

  const sorted = [...rows]
    .filter(r => !filter || r.name.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => {
      const dir = sortDir === 'desc' ? -1 : 1;
      if (sortBy === 'max_score')          return dir * ((a.max_score || 0) - (b.max_score || 0));
      if (sortBy === 'vulnerable_devices') return dir * ((a.vulnerable_devices || 0) - (b.vulnerable_devices || 0));
      if (sortBy === 'total_devices')      return dir * ((a.total_devices || 0) - (b.total_devices || 0));
      if (sortBy === 'vuln_pct')           return dir * ((a.vuln_pct || 0) - (b.vuln_pct || 0));
      if (sortBy === 'name')               return dir * a.name.localeCompare(b.name);
      return 0;
    });

  const estate = stats?.estate || {};
  const d = trends?.deltas || {};
  const hasTrend = !!trends?.previous;

  const handleExportAll = () => {
    window.open(`${apiBase}/api/export/all`, '_blank');
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] gap-4 text-gray-500">
        <RefreshCw size={24} className="animate-spin text-green-500" />
        <span className="text-sm">Loading estate data…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] gap-4">
        <AlertTriangle size={32} className="text-yellow-500" />
        <p className="text-sm text-gray-400 max-w-sm text-center">{error}</p>
        <button onClick={fetchAll} className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm text-gray-300 hover:text-white transition-colors">
          Retry
        </button>
      </div>
    );
  }

  const noData = rows.length === 0;

  return (
    <div className="p-4 md:p-6 space-y-6">

      {/* ── Page header ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-black text-white tracking-wide">Estate Overview</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            {estate.last_scan ? `Last scan: ${formatAge(estate.last_scan)}` : 'No scans yet — run a global scan to populate data'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAll}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-700 bg-gray-800 text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw size={11} /> Refresh
          </button>
          {rows.length > 0 && (
            <button
              onClick={handleExportAll}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-green-700/50 bg-green-900/20 text-green-400 hover:bg-green-900/40 transition-colors font-semibold"
            >
              <Download size={11} /> Export All (.xlsx)
            </button>
          )}
        </div>
      </div>

      {noData ? (
        <div className="flex flex-col items-center justify-center py-24 gap-4">
          <Shield size={40} className="text-gray-700" />
          <div className="text-center">
            <p className="text-gray-400 font-semibold">No scan data yet</p>
            <p className="text-gray-600 text-sm mt-1">Run a global scan or select a tenant to get started.</p>
          </div>
        </div>
      ) : (
        <>
          {/* ── Estate stat cards ── */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard
              icon={Shield} label="Clients Scanned" accent="text-green-400"
              value={fmt(estate.total_tenants)}
              delta={hasTrend ? d.total_tenants : null}
              tooltip="Number of unique NetBox tenants that have been scanned at least once. Click to view all scanned clients."
              onClick={() => setDrilldown({ type: 'clients', value: '', label: 'Scanned Clients' })}
            />
            <StatCard
              icon={Server} label="Total Devices"
              value={fmt(estate.total_devices)}
              sub={estate.physical_devices || estate.virtual_machines
                ? `${fmt(estate.physical_devices)} physical · ${fmt(estate.virtual_machines)} VMs`
                : undefined}
              delta={hasTrend ? d.total_devices : null}
              tooltip="Total physical devices and virtual machines across all scanned tenants. Click to view full device inventory."
              onClick={() => setDrilldown({ type: 'all_devices', value: '', label: 'All Devices' })}
            />
            <StatCard
              icon={AlertTriangle} label="Vulnerable" accent="text-orange-400"
              value={fmt(estate.vulnerable_devices)}
              sub={estate.total_devices ? `${Math.round(100 * (estate.vulnerable_devices || 0) / estate.total_devices)}% of estate` : ''}
              delta={hasTrend ? d.vulnerable_devices : null}
              deltaGoodWhenDown
              tooltip="Devices where the NVD API returned at least one matching CVE. Click to view all vulnerable devices."
              onClick={() => setDrilldown({ type: 'vulnerable', value: '', label: 'Vulnerable Devices' })}
            />
            <StatCard
              icon={AlertTriangle} label="Critical Devices"
              accent={estate.critical_devices > 0 ? 'text-red-500' : 'text-green-400'}
              value={fmt(estate.critical_devices)}
              sub="CVE score ≥ 9.0"
              delta={hasTrend ? d.critical_devices : null}
              deltaGoodWhenDown
              tooltip="Devices carrying at least one CVE with a CVSS score of 9.0 or higher. Click to view all critical devices."
              onClick={() => setDrilldown({ type: 'critical', value: '', label: 'Critical Devices (CVE Score ≥ 9.0)' })}
            />
            <StatCard
              icon={Bug} label="CVE Instances" accent="text-yellow-400"
              value={fmt(estate.total_cve_instances)}
              delta={hasTrend ? d.total_cves : null}
              deltaGoodWhenDown
              tooltip="Total count of individual CVE matches across all devices and all tenants. Click to view every CVE instance."
              onClick={() => setDrilldown({ type: 'cve_instances', value: '', label: 'All CVE Instances' })}
            />
            <StatCard
              icon={Activity} label="Peak CVE Score"
              accent={scoreColor(estate.max_score)}
              value={(estate.max_score || 0).toFixed(1)}
              delta={hasTrend ? d.peak_score : null}
              deltaGoodWhenDown
              deltaDecimals={1}
              tooltip="Highest individual CVE CVSS score found anywhere in the estate. Click to view all devices at this score."
              onClick={() => setDrilldown({ type: 'peak_score', value: '', label: `Devices at Peak Score (${(estate.max_score || 0).toFixed(1)})` })}
            />
          </div>

          {/* ── Info panels ── */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
            <SeverityPanel breakdown={stats?.severity_breakdown} onDrilldown={setDrilldown} />
            <PlatformPanel platforms={stats?.top_platforms} onDrilldown={setDrilldown} />
            <TopCvesPanel cves={stats?.top_cves} onDrilldown={setDrilldown} />
            <ScanTrendsPanel trends={trends} />
            <AiStatsPanel apiBase={apiBase} />
          </div>

          {/* ── Scan history ── */}
          <ScanHistoryPanel apiBase={apiBase} />

          {/* ── Leaderboard table ── */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                Customer Rankings — {sorted.length} client{sorted.length !== 1 ? 's' : ''}
              </span>
              <div className="relative w-full sm:w-56">
                <Search size={12} className="absolute left-2.5 top-2.5 text-gray-500" />
                <input
                  type="text"
                  placeholder="Filter by client name…"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-7 pr-7 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-green-500/50"
                />
                {filter && (
                  <button onClick={() => setFilter('')} className="absolute right-2.5 top-2.5 text-gray-500 hover:text-white">
                    <X size={11} />
                  </button>
                )}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-wider text-[10px]">
                    <th className="px-3 py-2 text-right w-10">#</th>
                    <th className="px-3 py-2 text-left">
                      <ThBtn field="name" current={sortBy} dir={sortDir} onSort={handleSort}>Client</ThBtn>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <ThBtn field="total_devices" current={sortBy} dir={sortDir} onSort={handleSort}>Devices</ThBtn>
                        <InfoTip content="Total physical devices and VMs for this tenant in NetBox." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <ThBtn field="vulnerable_devices" current={sortBy} dir={sortDir} onSort={handleSort}>Vulnerable</ThBtn>
                        <InfoTip content="Devices where the NVD API returned at least one CVE match. Devices without platform data are excluded from CVE scanning." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <ThBtn field="vuln_pct" current={sortBy} dir={sortDir} onSort={handleSort}>Vuln%</ThBtn>
                        <InfoTip content="Percentage of total devices that have at least one CVE. Higher percentages indicate broader exposure across the tenant's estate." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <ThBtn field="max_score" current={sortBy} dir={sortDir} onSort={handleSort}>CVE Score</ThBtn>
                        <InfoTip content="Highest CVSS score of any single CVE found across this tenant's devices. Red ≥ 9.0 (Critical), Orange ≥ 7.0 (High), Yellow ≥ 4.0 (Medium)." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-center">
                      <div className="flex items-center justify-center gap-1">
                        Risk
                        <InfoTip content="AI-generated overall risk posture for this tenant's estate. Derived from CVE severity, breadth of exposure, and device criticality by the LLM back-fill worker." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-center">
                      <div className="flex items-center justify-center gap-1">
                        Trend
                        <InfoTip content="AI-assessed direction of risk: improving (↓ fewer/lower CVEs than last scan), declining (↑ more/higher CVEs), or stable (—). Requires at least two scans to calculate." position="bottom" size={9} />
                      </div>
                    </th>
                    <th className="px-3 py-2 text-right hidden md:table-cell">Last Scan</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((row, i) => (
                    <tr
                      key={row.tenant_id}
                      onClick={() => onSelectTenant({ id: row.tenant_id, name: row.name })}
                      className="border-b border-gray-800/60 hover:bg-gray-800/60 cursor-pointer transition-colors"
                    >
                      <td className="px-3 py-2.5 text-right">
                        <RankBadge rank={i + 1} />
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="font-semibold text-white hover:text-green-400 transition-colors">
                          {row.name}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right font-mono text-gray-300">
                        {fmt(row.total_devices)}
                      </td>
                      <td className={`px-3 py-2.5 text-right font-mono font-bold ${row.vulnerable_devices > 0 ? 'text-orange-400' : 'text-green-500'}`}>
                        {fmt(row.vulnerable_devices)}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <div className="w-16 bg-gray-800 rounded-full h-1.5 overflow-hidden hidden sm:block">
                            <div
                              className="bg-orange-500/70 h-full rounded-full"
                              style={{ width: `${Math.min(row.vuln_pct || 0, 100)}%` }}
                            />
                          </div>
                          <span className="font-mono text-gray-400 w-10 text-right">
                            {(row.vuln_pct || 0).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <span className={`text-base font-black font-mono ${scoreColor(row.max_score)}`}>
                          {(row.max_score || 0).toFixed(1)}
                        </span>
                        {row.effective_max_score != null && row.effective_max_score < row.max_score && (
                          <div
                            className={`text-[10px] font-mono font-bold ${scoreColor(row.effective_max_score)}`}
                            title="Effective score: ignores CVEs that device configurations have ruled out (feature not enabled / already mitigated). Raw CVSS is shown above."
                          >
                            <span className="text-gray-500 font-normal">effective </span>{row.effective_max_score.toFixed(1)}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-center">
                        {row.risk_posture ? (
                          <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${postureStyle(row.risk_posture)}`}>
                            {row.risk_posture}
                          </span>
                        ) : (
                          <span className="text-gray-700">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-center">
                        <TrendIcon trend={row.trend} />
                      </td>
                      <td className="px-3 py-2.5 text-right text-gray-600 hidden md:table-cell">
                        {formatAge(row.scanned_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {sorted.length === 0 && filter && (
              <div className="py-8 text-center text-gray-600 text-sm">
                No clients matching "{filter}"
              </div>
            )}
          </div>
        </>
      )}

      <DrilldownModal
        drilldown={drilldown}
        onClose={() => setDrilldown(null)}
        apiBase={apiBase}
      />
    </div>
  );
}
