import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, TrendingUp, TrendingDown, Minus, RefreshCw, Download,
  ChevronUp, ChevronDown, Search, X, AlertTriangle, Activity,
  Server, Layers, Bug, Cpu, Zap, Clock, CheckCircle2, DatabaseZap,
  BarChart3, ListTodo,
} from 'lucide-react';

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
// Sub-panels
// ---------------------------------------------------------------------------
const StatCard = ({ label, value, sub, icon: Icon, accent = 'text-white', wide }) => (
  <div className={`bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-col gap-1 ${wide ? 'md:col-span-2' : ''}`}>
    <div className="flex items-center gap-2 text-gray-500 text-xs uppercase tracking-wider font-semibold">
      {Icon && <Icon size={12} />}{label}
    </div>
    <div className={`text-2xl font-black font-mono ${accent}`}>{value}</div>
    {sub && <div className="text-xs text-gray-600">{sub}</div>}
  </div>
);

const SeverityPanel = ({ breakdown }) => {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const total = Object.values(breakdown || {}).reduce((s, v) => s + v, 0);
  if (!total) return null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
        <AlertTriangle size={10} /> Severity Breakdown
      </div>
      <div className="space-y-2">
        {order.map(sev => {
          const count = breakdown[sev] || 0;
          if (!count) return null;
          const pct = Math.round((count / total) * 100);
          const cfg = SEV_CFG[sev] || SEV_CFG.UNKNOWN;
          return (
            <div key={sev}>
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

const PlatformPanel = ({ platforms }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
      <Layers size={10} /> Top Platforms by Exposure
    </div>
    <div className="space-y-2">
      {(platforms || []).slice(0, 8).map((p, i) => (
        <div key={i} className="flex items-center gap-2">
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

const TopCvesPanel = ({ cves }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
    <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
      <Bug size={10} /> Most Widespread CVEs
    </div>
    <div className="space-y-1.5">
      {(cves || []).slice(0, 8).map((c, i) => (
        <div key={i} className="flex items-start gap-2 group">
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

const MiniStat = ({ icon: Icon, label, value, accent = 'text-white', title }) => (
  <div className="flex flex-col gap-0.5" title={title}>
    <div className="flex items-center gap-1 text-[10px] text-gray-500 uppercase tracking-wider">
      {Icon && <Icon size={9} />}{label}
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
        <MiniStat icon={BarChart3}  label="Analyzed (24h)"   value={(ai.analyzed_last_24h ?? 0).toLocaleString()} accent="text-green-400" />
        <MiniStat icon={ListTodo}   label="In queue"          value={(ai.pending_devices ?? 0).toLocaleString()}   accent={ai.pending_devices > 0 ? 'text-yellow-400' : 'text-gray-400'} />
        <MiniStat icon={Server}     label="Tenants pending"   value={(ai.pending_tenants ?? 0).toLocaleString()}   />
        <MiniStat icon={Activity}   label="Session total"     value={(ai.total_analyzed ?? 0).toLocaleString()}    accent="text-purple-400" />
        <MiniStat icon={Zap}        label="API calls"         value={(ai.total_api_calls ?? 0).toLocaleString()}   />
        <MiniStat icon={DatabaseZap} label="Cache hits"       value={(ai.total_cache_hits ?? 0).toLocaleString()}  accent="text-blue-400" />
      </div>

      {/* Latency row */}
      <div className="border-t border-gray-800 pt-3 grid grid-cols-4 gap-2">
        <MiniStat icon={Clock} label="Avg latency"  value={fmtMs(ai.avg_latency_ms)}  accent="text-cyan-400" title="Rolling avg of last 100 real API calls" />
        <MiniStat label="P95"      value={fmtMs(ai.p95_latency_ms)} title="95th percentile latency" />
        <MiniStat label="Min"      value={fmtMs(ai.min_latency_ms)} accent="text-green-400" />
        <MiniStat label="Max"      value={fmtMs(ai.max_latency_ms)} accent={ai.max_latency_ms > 30000 ? 'text-red-400' : 'text-gray-300'} />
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
// Main component
// ---------------------------------------------------------------------------
export default function Leaderboard({ apiBase, onSelectTenant }) {
  const [stats, setStats] = useState(null);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortBy, setSortBy] = useState('max_score');
  const [sortDir, setSortDir] = useState('desc');
  const [filter, setFilter] = useState('');

  const fetchAll = useCallback(async () => {
    try {
      const [sRes, lRes] = await Promise.all([
        fetch(`${apiBase}/api/stats`),
        fetch(`${apiBase}/api/leaderboard?limit=500`),
      ]);
      if (!sRes.ok || !lRes.ok) throw new Error('API error');
      const [sData, lData] = await Promise.all([sRes.json(), lRes.json()]);
      setStats(sData);
      setRows(lData);
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
            <StatCard icon={Shield}    label="Clients Scanned"    value={fmt(estate.total_tenants)}     accent="text-green-400" />
            <StatCard icon={Server}    label="Total Devices"      value={fmt(estate.total_devices)}     />
            <StatCard icon={AlertTriangle} label="Vulnerable"     value={fmt(estate.vulnerable_devices)}
              sub={estate.total_devices ? `${Math.round(100 * (estate.vulnerable_devices || 0) / estate.total_devices)}% of estate` : ''}
              accent="text-orange-400"
            />
            <StatCard icon={AlertTriangle} label="Critical Devices" value={fmt(estate.critical_devices)}
              sub="CVE score ≥ 9.0" accent={estate.critical_devices > 0 ? 'text-red-500' : 'text-green-400'}
            />
            <StatCard icon={Bug}       label="CVE Instances"     value={fmt(estate.total_cve_instances)} accent="text-yellow-400" />
            <StatCard icon={Activity}  label="Peak CVE Score"    value={(estate.max_score || 0).toFixed(1)}
              accent={scoreColor(estate.max_score)}
            />
          </div>

          {/* ── Info panels ── */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <SeverityPanel breakdown={stats?.severity_breakdown} />
            <PlatformPanel platforms={stats?.top_platforms} />
            <TopCvesPanel cves={stats?.top_cves} />
            <AiStatsPanel apiBase={apiBase} />
          </div>

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
                      <ThBtn field="total_devices" current={sortBy} dir={sortDir} onSort={handleSort}>Devices</ThBtn>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <ThBtn field="vulnerable_devices" current={sortBy} dir={sortDir} onSort={handleSort}>Vulnerable</ThBtn>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <ThBtn field="vuln_pct" current={sortBy} dir={sortDir} onSort={handleSort}>Vuln%</ThBtn>
                    </th>
                    <th className="px-3 py-2 text-right">
                      <ThBtn field="max_score" current={sortBy} dir={sortDir} onSort={handleSort}>CVE Score</ThBtn>
                    </th>
                    <th className="px-3 py-2 text-center">Risk</th>
                    <th className="px-3 py-2 text-center">Trend</th>
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
    </div>
  );
}
