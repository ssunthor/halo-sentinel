import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Server, X, Router, Network, Shield, HardDrive, ChevronDown, ChevronUp, AlertTriangle, TrendingUp, TrendingDown, Minus, RefreshCw, Clock, Download, ShieldAlert, ShieldCheck, ShieldOff, Copy, CheckCheck } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { InfoTip } from './Tooltip';
import { CveConfigVerdict, ConfigCoverageNote } from './CveConfigVerdict';
import { useCveConfig } from './useCveConfig';

// ---------------------------------------------------------------------------
// SEVERITY HELPERS
// ---------------------------------------------------------------------------
const getSeverityBorderColor = (score) => {
  if (!score || score === 0) return 'border-green-500';
  if (score >= 7) return 'border-red-500';
  if (score >= 4) return 'border-orange-500';
  return 'border-yellow-500';
};

const getSeverityTextClass = (score) => {
  if (!score || score === 0) return 'text-green-500';
  if (score >= 7) return 'text-red-500';
  if (score >= 4) return 'text-orange-500';
  return 'text-yellow-500';
};

const getRiskPostureStyle = (posture) => {
  if (!posture) return { border: 'border-gray-700', text: 'text-gray-400', bg: 'bg-gray-900/50' };
  const p = posture.toLowerCase();
  if (p === 'critical') return { border: 'border-red-500/50', text: 'text-red-400', bg: 'bg-red-900/10' };
  if (p === 'high')     return { border: 'border-orange-500/50', text: 'text-orange-400', bg: 'bg-orange-900/10' };
  if (p === 'medium')   return { border: 'border-yellow-500/50', text: 'text-yellow-400', bg: 'bg-yellow-900/10' };
  if (p === 'low')      return { border: 'border-blue-500/50', text: 'text-blue-400', bg: 'bg-blue-900/10' };
  return { border: 'border-green-500/50', text: 'text-green-400', bg: 'bg-green-900/10' };
};

const getDeviceIcon = (deviceType) => {
  const type = (deviceType || '').toLowerCase();
  if (type.includes('virtual-machine') || type.includes('vm') || type.includes('cluster')) return <Server className="text-blue-400" />;
  if (type.includes('router')) return <Router className="text-gray-400" />;
  if (type.includes('switch')) return <Network className="text-gray-400" />;
  if (type.includes('firewall')) return <Shield className="text-gray-400" />;
  if (type.includes('server')) return <Server className="text-gray-400" />;
  return <HardDrive className="text-gray-400" />;
};

const TrendIcon = ({ trend }) => {
  if (!trend) return null;
  if (trend === 'improving') return <TrendingDown size={14} className="text-green-400" />;
  if (trend === 'declining') return <TrendingUp size={14} className="text-red-400" />;
  return <Minus size={14} className="text-gray-400" />;
};

const formatDate = (iso) => {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
};

// ---------------------------------------------------------------------------
// ESTATE SUMMARY PANEL
// ---------------------------------------------------------------------------
const EstateSummaryPanel = ({ summary, tenantName }) => {
  const [open, setOpen] = useState(true);
  if (!summary) return null;

  const style = getRiskPostureStyle(summary.risk_posture);

  return (
    <div className={`mb-4 rounded-xl border ${style.border} ${style.bg} overflow-hidden`}>
      {/* Header (always visible) */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/5 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Shield size={16} className={style.text} />
          <div className="text-left">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">Estate Risk Assessment</span>
              <InfoTip content="AI-generated summary of this tenant's overall security posture. The LLM analyzes the full CVE list, device count, severity distribution, and (if available) the previous scan's results to produce this assessment." position="bottom" />
              <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded ${style.text} border ${style.border}`}>
                {summary.risk_posture || 'Unknown'}
              </span>
              <InfoTip content="Overall risk posture: Critical (9.0+), High (7.0+), Medium (4.0+), Low (<4.0), or Clean (no CVEs). Determined by the LLM based on the severity and breadth of vulnerabilities across the estate." position="bottom" />
              {summary.trend && summary.trend !== 'new_scan' && (
                <span className="flex items-center gap-1 text-xs text-gray-400">
                  <TrendIcon trend={summary.trend} />
                  {summary.trend}
                  <InfoTip content="Risk trend compared to the previous scan. Improving = fewer or lower-severity CVEs, Declining = more or higher-severity CVEs, Stable = no significant change." position="bottom" />
                </span>
              )}
            </div>
            {summary.risk_summary && (
              <p className="text-xs text-gray-400 mt-0.5 max-w-2xl text-left">{summary.risk_summary}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <span className="text-xs text-gray-600 hidden md:block">
            {summary.vulnerable_device_count} / {summary.total_device_count} vulnerable
          </span>
          {open ? <ChevronUp size={16} className="text-gray-400" /> : <ChevronDown size={16} className="text-gray-400" />}
        </div>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="px-5 pb-5 border-t border-white/5 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
            {/* Stat cards */}
            <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
              <div className="flex items-center gap-1 text-xs text-gray-500 uppercase tracking-wider mb-1">
                Total Scanned
                <InfoTip content="Total physical devices and VMs in NetBox for this tenant that were included in the CVE scan." position="bottom" size={10} />
              </div>
              <div className="text-2xl font-black text-white">{summary.total_device_count ?? '—'}</div>
            </div>
            <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
              <div className="flex items-center gap-1 text-xs text-gray-500 uppercase tracking-wider mb-1">
                Vulnerable
                <InfoTip content="Devices where the NVD API returned at least one CVE match. Devices without a configured platform or OS version are excluded from CVE lookup." position="bottom" size={10} />
              </div>
              <div className={`text-2xl font-black ${style.text}`}>{summary.vulnerable_device_count ?? '—'}</div>
            </div>
            <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
              <div className="flex items-center gap-1 text-xs text-gray-500 uppercase tracking-wider mb-1">
                Max CVE Score
                <InfoTip content="Highest CVSS v3 base score found on any device in this tenant's estate. CVSS scores range from 0.0 to 10.0 — scores of 9.0+ are Critical severity." position="bottom" size={10} />
              </div>
              <div className={`text-2xl font-black ${getSeverityTextClass(summary.max_severity_score)}`}>
                {summary.max_severity_score != null ? summary.max_severity_score.toFixed(1) : '—'}
              </div>
            </div>
          </div>

          {/* Top CVEs */}
          {summary.top_cves && summary.top_cves.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                Top CVEs Across Estate
                <InfoTip content="The highest-scoring CVEs found on any device in this estate. Click any CVE ID to open the full NIST NVD detail page showing technical description, affected versions, and patch references." position="right" />
              </h4>
              <div className="space-y-1.5">
                {summary.top_cves.map((cve, i) => (
                  <div key={i} className="flex items-center gap-3 bg-black/20 rounded-lg px-3 py-2 border border-gray-800">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:underline text-xs font-bold font-mono flex-shrink-0 w-32"
                    >
                      {cve.id}
                    </a>
                    <span className={`text-xs font-bold flex-shrink-0 ${getSeverityTextClass(cve.score)}`}>
                      {cve.score?.toFixed(1)} {cve.severity}
                    </span>
                    <span className="text-xs text-gray-500 flex-shrink-0">
                      {cve.affected_count != null ? `${cve.affected_count} device(s)` : ''}
                    </span>
                    {cve.action && (
                      <span className="text-xs text-gray-400 truncate">{cve.action}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {summary.recommendations && summary.recommendations.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                Prioritized Recommendations
                <InfoTip content="AI-generated remediation steps ranked by urgency. Based on CVE severity scores, the number of affected devices, and exploitability factors from the NVD data." position="right" />
              </h4>
              <ol className="space-y-1.5">
                {summary.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-green-500/10 border border-green-500/30 text-green-400 text-xs flex items-center justify-center font-bold mt-0.5">
                      {i + 1}
                    </span>
                    {rec}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Trend detail */}
          {summary.trend_detail && summary.trend !== 'new_scan' && (
            <div className="flex items-start gap-2 bg-black/20 rounded-lg px-3 py-2 border border-gray-800">
              <TrendIcon trend={summary.trend} />
              <p className="text-xs text-gray-400">{summary.trend_detail}</p>
            </div>
          )}

          <p className="text-xs text-gray-700">
            Generated {formatDate(summary.generated_at)}
            {summary.previous_generated_at && ` · Previous: ${formatDate(summary.previous_generated_at)}`}
          </p>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// CONFIG ANALYSIS SECTION (FBA)
// ---------------------------------------------------------------------------
const SEV_STYLE = {
  CRITICAL: 'bg-red-900/30 text-red-400 border border-red-500/40',
  HIGH:     'bg-orange-900/30 text-orange-400 border border-orange-500/40',
  WARNING:  'bg-yellow-900/30 text-yellow-400 border border-yellow-500/40',
  INFO:     'bg-blue-900/30 text-blue-400 border border-blue-500/40',
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} className="ml-2 text-gray-600 hover:text-green-400 transition-colors flex-shrink-0" title="Copy to clipboard">
      {copied ? <CheckCheck size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
  );
}

// Why there is no FBA audit to show. These used to be one message ("No
// configuration profile found"), which was wrong for devices that simply had
// not been looked up yet or whose lookup had failed.
const FBA_EMPTY_STATE = {
  pending: 'Not checked against FBA yet — the lookup for this device is queued.',
  lookup_failed: 'The FBA lookup for this device failed (FBA unreachable or returned an error). It is retried automatically.',
  not_analyzed: "FBA holds this device's configuration but has not audited it yet.",
  not_found: 'No configuration profile found for this device in the FBA system.',
  not_applicable: 'FBA audits Fortinet devices only — this device is not looked up.',
};

const ConfigAnalysisSection = ({ deviceName, apiBase }) => {
  const [fba, setFba]         = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(false);
  const [rechecking, setRechecking] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(false);
    fetch(`${apiBase}/api/device/${encodeURIComponent(deviceName)}/fba`)
      .then(r => {
        if (r.status === 404) return null;
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => setFba(data))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, [deviceName, apiBase]);

  // Look the device up in FBA now instead of waiting for the background worker.
  const recheck = () => {
    setRechecking(true);
    fetch(`${apiBase}/api/device/${encodeURIComponent(deviceName)}/fba/refresh`, { method: 'POST' })
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(data => setFba(data))
      .catch(() => {})
      .finally(() => setRechecking(false));
  };

  if (loading) {
    return (
      <div className="p-4 bg-gray-800 rounded-lg">
        <h3 className="text-sm font-bold mb-2 text-cyan-400 flex items-center gap-2">
          <Shield size={14} /> Config Analysis
        </h3>
        <div className="flex items-center gap-2 text-gray-500 text-xs">
          <RefreshCw size={12} className="animate-spin" /> Loading config data…
        </div>
      </div>
    );
  }

  if (error || !fba) {
    return (
      <div className="p-4 bg-gray-800 rounded-lg">
        <h3 className="text-sm font-bold mb-2 text-cyan-400 flex items-center gap-2">
          <ShieldOff size={14} /> Config Analysis
        </h3>
        <p className="text-xs text-gray-600">
          {error ? 'Could not load config data.' : 'No configuration data available for this device.'}
        </p>
      </div>
    );
  }

  if (!fba.fba_analyzed) {
    return (
      <div className="p-4 bg-gray-800 rounded-lg">
        <h3 className="text-sm font-bold mb-2 text-cyan-400 flex items-center gap-2">
          <ShieldOff size={14} /> Config Analysis
        </h3>
        <p className="text-xs text-gray-600">{FBA_EMPTY_STATE[fba.fba_state] || FBA_EMPTY_STATE.not_found}</p>
        {fba.fba_lookup_error && (
          <p className="text-[11px] font-mono text-orange-400 mt-1 break-words">{fba.fba_lookup_error}</p>
        )}
        <button
          type="button"
          onClick={recheck}
          disabled={rechecking}
          className="mt-2 inline-flex items-center gap-1.5 text-[11px] text-cyan-400 hover:text-cyan-300 disabled:opacity-50"
        >
          <RefreshCw size={11} className={rechecking ? 'animate-spin' : ''} />
          {rechecking ? 'Checking FBA…' : 'Re-check FBA now'}
        </button>
      </div>
    );
  }

  const findings = fba.fba_findings || [];
  const isVuln   = fba.fba_vulnerable;

  return (
    <div className="p-4 bg-gray-800 rounded-lg space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-2">
          {isVuln ? <ShieldAlert size={14} className="text-red-400" /> : <ShieldCheck size={14} className="text-green-400" />}
          Config Analysis
          <InfoTip content="Live configuration analysis from the FBA (Firewall Baseline Analyzer) system. Results reflect the device's actual running config and may confirm or rule out CVE exploitability." position="left" size={10} />
        </h3>
        {fba.fba_scanned_at && (
          <span className="text-[10px] text-gray-600">
            Checked: {new Date(fba.fba_scanned_at).toLocaleString()}
          </span>
        )}
      </div>

      {/* Status banner */}
      <div className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold ${isVuln ? 'bg-red-900/20 border border-red-500/30 text-red-300' : 'bg-green-900/20 border border-green-500/30 text-green-300'}`}>
        {isVuln ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
        {isVuln ? 'Configuration vulnerabilities detected' : 'No configuration vulnerabilities found'}
      </div>

      {/* Flag indicators */}
      <div className="flex gap-2 flex-wrap">
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${fba.fba_vuln_acl ? 'bg-red-900/30 text-red-400 border-red-500/40' : 'bg-gray-900 text-gray-600 border-gray-700'}`}>
          ACL {fba.fba_vuln_acl ? 'EXPOSED' : 'OK'}
        </span>
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${fba.fba_vuln_password ? 'bg-orange-900/30 text-orange-400 border-orange-500/40' : 'bg-gray-900 text-gray-600 border-gray-700'}`}>
          PASSWORD {fba.fba_vuln_password ? 'WEAK' : 'OK'}
        </span>
      </div>

      {/* Reason */}
      {fba.fba_reason && (
        <p className="text-xs text-gray-400 leading-relaxed">{fba.fba_reason}</p>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-2">
          <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Findings ({findings.length})</p>
          {findings.map((f, i) => (
            <div key={i} className="bg-gray-900 rounded-lg p-3 space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_STYLE[f.severity] || SEV_STYLE.INFO}`}>
                  {f.severity}
                </span>
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">{f.category}</span>
                {f.node && (
                  <span className="text-[10px] text-blue-400 font-mono bg-blue-900/30 px-1.5 py-0.5 rounded">{f.node}</span>
                )}
              </div>
              <p className="text-xs text-gray-300">{f.issue}</p>
              {f.remediation_script && (
                <div className="mt-1.5">
                  <div className="flex items-center gap-1 mb-1">
                    <span className="text-[10px] text-gray-600 uppercase tracking-wider">Remediation</span>
                    <CopyButton text={f.remediation_script.replace(/\\n/g, '\n')} />
                  </div>
                  <pre className="text-[10px] text-green-400 font-mono bg-black/40 rounded p-2 overflow-x-auto whitespace-pre-wrap">
                    {f.remediation_script.replace(/\\n/g, '\n')}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// MAIN COMPONENT
// ---------------------------------------------------------------------------
const NetboxVulnerabilities = ({ apiBase, tenantId, tenantName }) => {
  const [devices, setDevices] = useState([]);
  const [summary, setSummary] = useState(null);
  const [scanStatus, setScanStatus] = useState('idle'); // idle | running | complete | refreshing
  const [scanned, setScanned] = useState(0);
  const [total, setTotal] = useState(0);
  const [staleNotice, setStaleNotice] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const cveConfig = useCveConfig(selectedDevice?.resource_name, apiBase);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(25);
  const [showUnknown, setShowUnknown] = useState(true);
  const [showVMs, setShowVMs] = useState(true);

  const isScanning = scanStatus === 'running' || scanStatus === 'refreshing';

  const eventSourceRef = useRef(null);
  const devicesRef = useRef({});
  const summaryPollRef = useRef(null);

  const closeSse = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  const stopSummaryPoll = useCallback(() => {
    if (summaryPollRef.current) {
      clearInterval(summaryPollRef.current);
      summaryPollRef.current = null;
    }
  }, []);

  // Poll for summary until it arrives (LLM generation can take 30+ seconds for large estates).
  // Does an immediate fetch first, then retries every 5s up to ~5 minutes.
  const pollForSummary = useCallback(() => {
    stopSummaryPoll();
    let attempts = 0;
    const MAX_ATTEMPTS = 60;

    const tryFetch = async () => {
      attempts++;
      try {
        const res = await fetch(`${apiBase}/api/results/${tenantId}/summary`);
        if (res.ok) {
          const data = await res.json();
          if (data) {
            setSummary(data);
            stopSummaryPoll();
            return;
          }
        }
      } catch (e) {
        console.error('Error polling for summary:', e);
      }
      if (attempts >= MAX_ATTEMPTS) stopSummaryPoll();
    };

    // Fire immediately, then every 5s
    tryFetch();
    summaryPollRef.current = setInterval(tryFetch, 5000);
  }, [apiBase, tenantId, stopSummaryPoll]);

  // Open SSE stream (called after scan is triggered or when tenant loads)
  const openSse = useCallback(() => {
    closeSse();
    devicesRef.current = {};

    const es = new EventSource(`${apiBase}/api/results/${tenantId}/stream`);
    eventSourceRef.current = es;

    es.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'device') {
          const d = msg.data;
          devicesRef.current[d.resource_name] = d;
          const list = Object.values(devicesRef.current).sort(
            (a, b) => (b.highest_severity_score || 0) - (a.highest_severity_score || 0)
          );
          setDevices([...list]);

          const done = list.filter(x => x.llm_analysis !== 'Scanning...').length;
          setScanned(done);
          setTotal(list.length);
        } else if (msg.type === 'complete') {
          setScanStatus('complete');
          closeSse();
          pollForSummary();
        }
      } catch (e) {
        console.error('SSE parse error:', e);
      }
    };

    es.onerror = () => {
      // SSE closed by server is normal — check if scan completed
      closeSse();
    };
  }, [apiBase, tenantId, closeSse, pollForSummary]);

  // Manually force a fresh scan, bypassing cache
  const triggerManualScan = useCallback(async () => {
    if (isScanning) return;
    setDevices([]);
    setSummary(null);
    setScanStatus('running');
    setScanned(0);
    setTotal(0);
    setStaleNotice(null);
    setCurrentPage(1);
    devicesRef.current = {};
    stopSummaryPoll();
    try {
      await fetch(`${apiBase}/api/scan/${tenantId}?tenant_name=${encodeURIComponent(tenantName)}&force=true`, { method: 'POST' });
    } catch (e) {
      console.error('Error triggering manual scan:', e);
    }
    openSse();
  }, [apiBase, tenantId, tenantName, isScanning, closeSse, stopSummaryPoll, openSse]);

  // Main effect: runs when tenantId changes
  useEffect(() => {
    if (!tenantId) return;

    // Reset state for new tenant
    setDevices([]);
    setSummary(null);
    setScanStatus('idle');
    setScanned(0);
    setTotal(0);
    setStaleNotice(null);
    setCurrentPage(1);
    devicesRef.current = {};
    closeSse();

    const init = async () => {
      // 1. Trigger scan (backend handles cache freshness logic)
      try {
        const res = await fetch(`${apiBase}/api/scan/${tenantId}?tenant_name=${encodeURIComponent(tenantName)}`, { method: 'POST' });
        const data = await res.json();

        if (data.status === 'cached') {
          // Cache fresh — just load results
          setScanStatus('complete');
          const r2 = await fetch(`${apiBase}/api/results/${tenantId}`);
          const cached = await r2.json();
          const list = cached.devices || [];
          devicesRef.current = Object.fromEntries(list.map(d => [d.resource_name, d]));
          setDevices(list);
          setTotal(list.length);
          setScanned(list.length);
          pollForSummary();
          return;
        }

        if (data.status === 'refreshing') {
          setStaleNotice(data.message);
          setScanStatus('refreshing');
          // Load existing stale results while the new scan runs
          const r2 = await fetch(`${apiBase}/api/results/${tenantId}`);
          const cached = await r2.json();
          const list = cached.devices || [];
          devicesRef.current = Object.fromEntries(list.map(d => [d.resource_name, d]));
          setDevices(list);
          pollForSummary();
        } else {
          setScanStatus('running');
        }
      } catch (e) {
        console.error('Error triggering scan:', e);
        setScanStatus('running');
      }

      // 2. Open SSE to receive live updates
      openSse();
    };

    init();

    return () => { closeSse(); stopSummaryPoll(); };
  }, [tenantId]); // intentionally only on tenantId change

  // Dismiss stale notice once scan completes
  useEffect(() => {
    if (scanStatus === 'complete') setStaleNotice(null);
  }, [scanStatus]);

  // Filtering
  const filteredDevices = devices.filter(d => {
    const search = searchTerm.toLowerCase();
    const searchMatch = (
      (d.resource_name || '').toLowerCase().includes(search) ||
      (d.resource_type || '').toLowerCase().includes(search) ||
      (d.os || '').toLowerCase().includes(search)
    );
    const unknownMatch = showUnknown || (d.cves && d.cves.length > 0);
    const vmMatch = showVMs || d.resource_category !== 'vm';
    return searchMatch && unknownMatch && vmMatch;
  });

  const scanProgress = total > 0 ? Math.round((scanned / total) * 100) : 0;
  const effectiveItemsPerPage = itemsPerPage === 'All' ? filteredDevices.length : parseInt(itemsPerPage);
  const totalPages = Math.ceil(filteredDevices.length / (effectiveItemsPerPage || 1));
  const pageItems = filteredDevices.slice(
    (currentPage - 1) * (effectiveItemsPerPage || filteredDevices.length),
    currentPage * (effectiveItemsPerPage || filteredDevices.length)
  );

  return (
    <div className="p-4 bg-black text-white min-h-screen">

      {/* STALE CACHE NOTICE */}
      {staleNotice && (
        <div className="mb-4 flex items-center gap-3 bg-yellow-900/20 border border-yellow-500/30 rounded-xl px-4 py-3">
          <Clock size={14} className="text-yellow-400 flex-shrink-0" />
          <p className="text-sm text-yellow-300 flex-grow">{staleNotice}</p>
          <button onClick={() => setStaleNotice(null)} className="text-yellow-500 hover:text-white">
            <X size={14} />
          </button>
        </div>
      )}

      {/* SCAN PROGRESS */}
      {isScanning && (
        <div className="mb-4 bg-gray-900/50 p-4 rounded-xl border border-gray-800 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-bold text-green-500 uppercase tracking-widest flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-ping" />
              {scanStatus === 'refreshing' ? 'Refreshing scan in background...' : 'Vulnerability Scan in Progress...'}
              <InfoTip content={scanStatus === 'refreshing' ? 'A background rescan is running. Stale results are shown now — the device list will update as new results stream in.' : 'Devices are being queried against the NIST NVD API one by one. Results appear in real time as each device is processed. The most critical devices are sorted to the top automatically.'} position="bottom" />
            </span>
            <span className="text-sm font-black text-white">{scanProgress}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-3 border border-gray-700 overflow-hidden">
            <div
              className="bg-gradient-to-r from-green-600 to-green-400 h-full transition-all duration-1000 ease-out shadow-[0_0_10px_rgba(34,197,94,0.5)]"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
          <div className="flex justify-between mt-2">
            <p className="text-[10px] text-gray-500 uppercase font-bold">Processing {scanned} of {total} resources</p>
            <p className="text-[10px] text-gray-400 font-mono italic">Real-time update active</p>
          </div>
        </div>
      )}

      {/* ESTATE SUMMARY */}
      <EstateSummaryPanel summary={summary} tenantName={tenantName} />

      {/* HEADER + FILTERS */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-4 gap-4 bg-gray-900/50 p-4 rounded-xl border border-gray-800">
        <div className="flex items-center gap-3">
          <div>
            <h2 className="text-2xl font-bold text-green-500">{tenantName} — Vulnerabilities</h2>
            <p className="text-xs text-gray-500">Showing {filteredDevices.length} of {devices.length} resources</p>
          </div>
          <button
            onClick={triggerManualScan}
            disabled={isScanning}
            title="Force a fresh scan"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors disabled:opacity-40 disabled:cursor-not-allowed bg-gray-800 border-gray-700 text-gray-300 hover:bg-green-900/40 hover:border-green-500/50 hover:text-green-400"
          >
            <RefreshCw size={12} className={isScanning ? 'animate-spin' : ''} />
            Rescan
          </button>
          {devices.length > 0 && !isScanning && (
            <button
              onClick={() => window.open(`${apiBase}/api/export/tenant/${tenantId}`, '_blank')}
              title="Export to Excel"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors bg-gray-800 border-gray-700 text-gray-300 hover:bg-green-900/40 hover:border-green-500/50 hover:text-green-400"
            >
              <Download size={12} />
              Export .xlsx
            </button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          <div className="relative flex-grow md:flex-grow-0">
            <input
              type="text"
              placeholder="Search name, model, os..."
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              className="bg-gray-800 border border-gray-700 rounded-lg py-2 px-4 text-sm w-full md:w-64 focus:outline-none focus:ring-2 focus:ring-green-500/50"
            />
            {searchTerm && (
              <button onClick={() => setSearchTerm('')} className="absolute right-2 top-2 text-gray-500 hover:text-white">
                <X size={16} />
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Show:</label>
            <select
              value={itemsPerPage}
              onChange={(e) => { setItemsPerPage(e.target.value); setCurrentPage(1); }}
              className="bg-gray-800 border border-gray-700 rounded-lg p-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-green-500/50"
            >
              {[10, 25, 100, 'All'].map(v => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm cursor-pointer select-none">
            <input type="checkbox" checked={showUnknown} onChange={() => setShowUnknown(v => !v)} className="accent-green-500" />
            Unknown
            <InfoTip content="Show devices with a CVE score of 0.0 — either no vulnerabilities were found, or the device has no platform/OS data configured in NetBox. Uncheck to focus only on devices with confirmed CVEs." position="top" size={10} />
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer select-none">
            <input type="checkbox" checked={showVMs} onChange={() => setShowVMs(v => !v)} className="accent-green-500" />
            Virtual Machines
            <InfoTip content="Show virtual machines from NetBox Virtualization. Uncheck to see only physical devices. VMs are identified by the blue server icon." position="top" size={10} />
          </label>
        </div>
      </div>

      {/* DEVICE LIST */}
      {devices.length === 0 && scanStatus === 'idle' ? (
        <div className="flex items-center justify-center h-40 text-gray-500 text-sm">
          <RefreshCw size={14} className="animate-spin mr-2" /> Initializing scan...
        </div>
      ) : (
        <>
          {/* Column legend */}
          <div className="flex items-center px-3 py-1 text-[10px] text-gray-600 uppercase tracking-widest font-bold">
            <div className="w-10 flex-shrink-0" />
            <div className="flex-grow mx-4 flex items-center gap-1">
              Device
              <InfoTip content="Border color indicates CVE severity: green = clean (no CVEs), yellow = low (< 4.0), orange = medium/high (4.0–8.9), red = critical (≥ 9.0). Click any row to see the full CVE list and AI analysis." position="right" size={9} />
            </div>
            <div className="w-48 text-right hidden md:block">OS / Platform</div>
            <div className="w-20 text-right flex items-center justify-end gap-1">
              CVE Score
              <InfoTip content="Highest CVSS v3 base score across all CVEs found for this device. 0.0 = clean or no platform data. Spinning icon = NVD query in progress." position="left" size={9} />
            </div>
          </div>
          <div className="space-y-2">
            {pageItems.map((device) => (
              <div
                key={device.resource_name}
                className={`flex items-center p-3 bg-gray-900/50 rounded-lg border-l-4 transition-all duration-300 hover:bg-gray-800/70 cursor-pointer ${getSeverityBorderColor(device.highest_severity_score)}`}
                onClick={() => setSelectedDevice(device)}
              >
                <div className="flex-shrink-0 w-10 h-10 flex items-center justify-center">
                  {getDeviceIcon(device.resource_type)}
                </div>
                <div className="flex-grow mx-4 min-w-0">
                  <h3 className="text-sm font-bold text-white truncate" title={(device.resource_name || '').toUpperCase()}>
                    {(device.resource_name || '').toUpperCase()}
                  </h3>
                  <p className="text-xs text-gray-500 truncate">{device.resource_type}</p>
                </div>
                <div className="flex-shrink-0 w-48 min-w-0 hidden md:flex flex-col items-end gap-0.5">
                  <span className="text-xs text-green-500/70 truncate max-w-full" title={device.os}>{device.os}</span>
                  {device.recommended_version && (
                    <span className="text-[10px] text-amber-400/80 font-mono truncate max-w-full" title={`NVD Min Fix: ${device.recommended_version}`}>
                      NVD → {device.recommended_version}
                    </span>
                  )}
                  {device.gia_recommended_version && (
                    <span className="text-[10px] text-blue-400/80 font-mono truncate max-w-full" title={`Engineering Recommended: ${device.gia_recommended_version}`}>
                      Eng ★ {device.gia_recommended_version}
                    </span>
                  )}
                </div>
                <div className="flex-shrink-0 w-20 text-right">
                  {device.llm_analysis === 'Scanning...' ? (
                    <RefreshCw size={14} className="animate-spin text-gray-600 ml-auto" />
                  ) : (
                    <span className="flex flex-col items-end leading-tight">
                      <span className={`text-lg font-black ${getSeverityTextClass(device.highest_severity_score)}`}>
                        {device.highest_severity_score > 0 ? device.highest_severity_score.toFixed(1) : '0.0'}
                      </span>
                      {device.effective_severity_score != null && device.effective_severity_score < device.highest_severity_score && (
                        <span
                          className={`text-[10px] font-mono font-bold ${getSeverityTextClass(device.effective_severity_score)}`}
                          title="Effective score: highest CVSS among the CVEs this device's running configuration has NOT ruled out (feature not enabled / already mitigated). The raw CVSS score above is unchanged."
                        >
                          <span className="text-gray-500 font-normal">effective </span>{device.effective_severity_score.toFixed(1)}
                        </span>
                      )}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* PAGINATION */}
          {itemsPerPage !== 'All' && totalPages > 1 && (
            <div className="flex justify-center items-center gap-2 mt-8 pb-8">
              <button
                onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
                disabled={currentPage === 1}
                className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 disabled:opacity-30 hover:bg-gray-700 transition-colors"
              >
                Previous
              </button>
              <div className="flex gap-1">
                {[...Array(totalPages)].map((_, i) => {
                  const n = i + 1;
                  if (n === 1 || n === totalPages || (n >= currentPage - 1 && n <= currentPage + 1)) {
                    return (
                      <button
                        key={n}
                        onClick={() => setCurrentPage(n)}
                        className={`w-10 h-10 rounded-lg border ${currentPage === n ? 'bg-green-600 border-green-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'}`}
                      >
                        {n}
                      </button>
                    );
                  } else if (n === currentPage - 2 || n === currentPage + 2) {
                    return <span key={n} className="px-1 self-center text-gray-600">…</span>;
                  }
                  return null;
                })}
              </div>
              <button
                onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 disabled:opacity-30 hover:bg-gray-700 transition-colors"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {/* DEVICE DETAIL MODAL */}
      {selectedDevice && (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 p-6 rounded-xl max-w-3xl w-full border-2 border-gray-700 max-h-[90vh] flex flex-col">
            <div className="flex justify-between items-center mb-4 flex-shrink-0">
              <div>
                <h2 className="text-2xl font-bold text-green-500">{(selectedDevice.resource_name || '').toUpperCase()}</h2>
                <p className="text-xs text-gray-500 mt-1">{selectedDevice.resource_type} · {selectedDevice.os}</p>
                {(selectedDevice.gia_recommended_version || selectedDevice.recommended_version) && (
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1.5">
                    {selectedDevice.gia_recommended_version && (
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider">Engineering Rec:</span>
                        <span className="text-xs font-mono font-bold text-blue-400">{selectedDevice.gia_recommended_version}</span>
                      </div>
                    )}
                    {selectedDevice.recommended_version && (
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider">NVD Min Fix:</span>
                        <span className="text-xs font-mono font-bold text-amber-400">{selectedDevice.recommended_version}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
              <button onClick={() => setSelectedDevice(null)} className="text-gray-400 hover:text-white p-1">
                <X size={20} />
              </button>
            </div>
            <div className="overflow-y-auto flex-grow space-y-4 pr-1">
              {selectedDevice.cves && selectedDevice.cves.length > 0 && (
                <ConfigCoverageNote cveConfig={cveConfig} />
              )}
              {selectedDevice.cves && selectedDevice.cves.length > 0 ? (
                selectedDevice.cves.map((cve, i) => (
                  <div key={i} className="p-4 bg-gray-800 rounded-lg">
                    <div className="flex justify-between items-center">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:underline font-bold font-mono"
                      >
                        {cve.id}
                      </a>
                      <span className={`font-bold flex items-center gap-1.5 ${getSeverityTextClass(cve.score)}`}>
                        {cve.severity} — {cve.score}
                        <InfoTip content={`CVSS v3 base score ${cve.score}: ${cve.severity}. Scores reflect exploitability and impact but not your specific network exposure. Click the CVE ID to view full NVD details including vector string and known exploits.`} position="left" size={10} />
                      </span>
                    </div>
                    <p className="mt-2 text-gray-300 text-sm">{cve.description}</p>
                    <CveConfigVerdict key={`${selectedDevice.resource_name}-${cve.id}`} verdict={cveConfig?.verdicts?.[cve.id]} />
                  </div>
                ))
              ) : (
                <p className="text-gray-400">No vulnerabilities found for this device.</p>
              )}
              <div className="p-4 bg-gray-800 rounded-lg">
                <h3 className="text-lg font-bold mb-2 text-yellow-500 flex items-center gap-2">
                  AI Analysis
                  <InfoTip content="LLM-generated security assessment for this specific device. When FBA config data is available, the AI cross-references CVEs against the live device configuration to identify which vulnerabilities are actively exploitable." position="left" size={11} />
                </h3>
                {selectedDevice.llm_analysis === 'Scanning...' || selectedDevice.llm_analysis === 'Analyzing vulnerabilities...' ? (
                  <div className="flex items-center gap-2 text-gray-400 text-sm">
                    <RefreshCw size={14} className="animate-spin" /> Generating analysis...
                  </div>
                ) : (
                  <ReactMarkdown remarkPlugins={[remarkGfm]} className="prose prose-invert prose-sm">
                    {(selectedDevice.llm_analysis || 'No AI analysis available.').replace(/\n/g, '  \n')}
                  </ReactMarkdown>
                )}
              </div>

              <ConfigAnalysisSection
                deviceName={selectedDevice.resource_name}
                apiBase={apiBase}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NetboxVulnerabilities;
