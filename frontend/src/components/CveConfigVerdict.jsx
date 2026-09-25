import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, ShieldOff, ShieldQuestion, Wrench, FileCode, ChevronDown, ChevronUp, Copy, CheckCheck } from 'lucide-react';
import { InfoTip } from './Tooltip';

// ---------------------------------------------------------------------------
// Config-aware CVE applicability: is this CVE actually exploitable on THIS
// device, given its running config? Data comes from
// GET /api/device/{name}/cve-config — verdict, rationale, evidence snippets
// (sliced from the device's real, redacted config) and a suggested change.
// ---------------------------------------------------------------------------

const VERDICTS = {
  exploitable: {
    label: 'Exploitable', Icon: ShieldAlert,
    style: 'bg-red-900/30 text-red-400 border-red-500/40',
    tip: "The device's running configuration shows the vulnerable feature enabled and reachable.",
  },
  mitigated: {
    label: 'Mitigated by config', Icon: ShieldCheck,
    style: 'bg-green-900/30 text-green-400 border-green-500/40',
    tip: 'The vulnerable feature is enabled, but the configuration already restricts who can reach it. Patching is still the real fix.',
  },
  not_applicable: {
    label: 'Feature not enabled', Icon: ShieldOff,
    style: 'bg-gray-900 text-gray-400 border-gray-600',
    tip: 'The software version matches, but the vulnerable feature is not enabled in this device\'s configuration.',
  },
  config_independent: {
    label: 'Patch required', Icon: Wrench,
    style: 'bg-orange-900/30 text-orange-400 border-orange-500/40',
    tip: 'Exploitability does not depend on configuration — no config change helps. Upgrade to a fixed release.',
  },
  undetermined: {
    label: 'Config inconclusive', Icon: ShieldQuestion,
    style: 'bg-yellow-900/20 text-yellow-500 border-yellow-600/40',
    tip: 'The configuration does not settle whether this CVE is reachable. Treat it as applicable.',
  },
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

// Snippet with the real config line numbers in the gutter.
function ConfigSnippet({ evidence }) {
  const lines = (evidence.snippet || '').split('\n');
  return (
    <div>
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        <FileCode size={11} className="text-cyan-500 flex-shrink-0" />
        <span className="text-[10px] font-mono text-cyan-400">{evidence.section || 'config'}</span>
        <span className="text-[10px] text-gray-600">
          lines {evidence.start_line}{evidence.end_line !== evidence.start_line ? `–${evidence.end_line}` : ''}
        </span>
      </div>
      <pre className="text-[10px] font-mono bg-black/40 rounded p-2 overflow-x-auto leading-relaxed">
        {lines.map((l, i) => (
          <div key={i} className="flex">
            <span className="w-10 flex-shrink-0 text-right pr-2 mr-2 text-gray-600 border-r border-gray-800 select-none">
              {evidence.start_line + i}
            </span>
            <span className="text-gray-300 whitespace-pre">{l || ' '}</span>
          </div>
        ))}
      </pre>
      {evidence.note && <p className="text-[11px] text-gray-500 mt-1">{evidence.note}</p>}
    </div>
  );
}

export function ConfigCoverageNote({ cveConfig }) {
  if (!cveConfig) return null;
  if (!cveConfig.has_config) {
    return (
      <p className="text-[11px] text-gray-600 flex items-center gap-1.5">
        <ShieldQuestion size={11} />
        No device configuration available — CVEs below are matched by software version only.
      </p>
    );
  }
  const c = cveConfig.config || {};
  const n = Object.keys(cveConfig.verdicts || {}).length;
  return (
    <p className="text-[11px] text-gray-500 flex items-center gap-1.5 flex-wrap">
      <FileCode size={11} className="text-cyan-500" />
      Checked against the device's running configuration
      <span className="text-gray-600">
        ({c.source === 'fba' ? 'from FBA' : 'pushed from Halo'}, {c.line_count?.toLocaleString()} lines
        {c.fetched_at ? `, ${new Date(c.fetched_at).toLocaleDateString()}` : ''})
      </span>
      {n === 0 && <span className="text-gray-600">— analysis pending</span>}
    </p>
  );
}

export function CveConfigVerdict({ verdict }) {
  const [open, setOpen] = useState(verdict?.verdict === 'exploitable');
  if (!verdict || !VERDICTS[verdict.verdict]) return null;
  const v = VERDICTS[verdict.verdict];
  const evidence = verdict.evidence || [];
  const absent = verdict.absent_sections || [];
  const change = verdict.suggested_change || '';
  const hasDetail = evidence.length > 0 || absent.length > 0 || change || verdict.rationale;

  return (
    <div className="mt-3 border-t border-gray-700/60 pt-3">
      <button
        type="button"
        onClick={() => hasDetail && setOpen(o => !o)}
        className="w-full flex items-center gap-2 text-left"
      >
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${v.style}`}>
          <v.Icon size={11} /> {v.label.toUpperCase()}
        </span>
        <InfoTip content={v.tip} position="right" size={10} />
        {verdict.stale && (
          <span className="text-[10px] text-yellow-600" title="The device config has changed since this verdict; re-analysis is queued.">
            config changed — re-analysis queued
          </span>
        )}
        <span className="flex-grow" />
        {hasDetail && (
          <span className="text-[10px] text-gray-500 flex items-center gap-1">
            {evidence.length > 0 && `${evidence.length} config reference${evidence.length > 1 ? 's' : ''}`}
            {change && (evidence.length > 0 ? ' · fix available' : 'fix available')}
            {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </span>
        )}
      </button>

      {open && hasDetail && (
        <div className="mt-2 space-y-3">
          {verdict.rationale && <p className="text-xs text-gray-400 leading-relaxed">{verdict.rationale}</p>}

          {evidence.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Current configuration</p>
              {evidence.map((ev, i) => <ConfigSnippet key={i} evidence={ev} />)}
            </div>
          )}

          {absent.length > 0 && (
            <p className="text-[11px] text-gray-500">
              Not present in the configuration:{' '}
              {absent.map((s, i) => (
                <span key={i} className="font-mono text-gray-400 bg-black/40 rounded px-1 py-0.5 mr-1">{s}</span>
              ))}
            </p>
          )}

          {change && (
            <div>
              <div className="flex items-center gap-1 mb-1">
                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Suggested configuration change</span>
                <CopyButton text={change} />
              </div>
              <pre className="text-[10px] text-green-400 font-mono bg-black/40 rounded p-2 overflow-x-auto whitespace-pre-wrap">{change}</pre>
              {verdict.change_note && <p className="text-[11px] text-gray-500 mt-1">{verdict.change_note}</p>}
              <p className="text-[10px] text-gray-600 mt-1">
                AI-generated — review before applying. This reduces exposure; upgrading firmware remains the fix.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
