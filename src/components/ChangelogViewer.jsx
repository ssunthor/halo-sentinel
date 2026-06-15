import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronUp, CheckCircle, BookOpen, BarChart3 } from 'lucide-react';
import { Tooltip, InfoTip } from './Tooltip';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const getCategoryIcon = (catString) => {
  const match = catString.match(/^[^\w\s]+/);
  return match ? match[0] : '📌';
};

const renderItemWithNeedsDocs = (itemString) => {
  const tag = '[NEEDS_DOCS]';
  if (!itemString.includes(tag)) return itemString;
  const parts = itemString.split(tag);
  return (
    <>
      {parts.map((part, i) => (
        <React.Fragment key={i}>
          {part}
          {i < parts.length - 1 && (
            <InfoTip
              content="Documentation for this feature is pending"
              position="right"
              size={10}
              className="ml-1 align-middle"
            />
          )}
        </React.Fragment>
      ))}
    </>
  );
};

const StatBadge = ({ cat, count }) => (
  <Tooltip content={`${count} ${cat.replace(/^[^\w\s]+/, '').trim()}`} position="bottom">
    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border border-gray-700 bg-gray-800 text-[11px] font-bold text-gray-300 whitespace-nowrap">
      {getCategoryIcon(cat)} {count}
    </span>
  </Tooltip>
);

const StatBadges = ({ stats }) => (
  <div className="flex items-center gap-1.5 flex-wrap">
    {Object.entries(stats).map(([cat, count]) => (
      <StatBadge key={cat} cat={cat} count={count} />
    ))}
  </div>
);

// ---------------------------------------------------------------------------
// Accordion
// ---------------------------------------------------------------------------
const Accordion = ({ header, children, defaultExpanded = false, nested = false }) => {
  const [open, setOpen] = useState(defaultExpanded);
  return (
    <div className={`border border-gray-800 overflow-hidden ${nested ? '' : 'rounded-lg mb-2'}`}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center justify-between text-left transition-colors ${
          nested
            ? 'px-4 py-2.5 bg-gray-900 hover:bg-gray-800/80 border-b border-gray-800'
            : 'px-4 py-3 bg-gray-900/80 hover:bg-gray-800/60'
        }`}
      >
        <div className="flex-grow min-w-0 pr-3">{header}</div>
        {open
          ? <ChevronUp size={14} className="text-gray-500 flex-shrink-0" />
          : <ChevronDown size={14} className="text-gray-500 flex-shrink-0" />
        }
      </button>
      {open && <div className="bg-gray-950">{children}</div>}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Change list (body of each release)
// ---------------------------------------------------------------------------
const renderChanges = (changes) => (
  <div className="px-4 py-4 space-y-4">
    {(changes || []).map((category, i) => (
      <div key={i}>
        <div className="text-[10px] font-bold text-green-400 uppercase tracking-widest mb-2">
          {category.category}
        </div>
        <div className="space-y-1.5">
          {(category.items || []).map((item, j) => (
            <div key={j} className="flex items-start gap-2">
              <CheckCircle size={12} className="text-gray-700 flex-shrink-0 mt-0.5" />
              <span className="text-xs text-gray-300 leading-relaxed">
                {renderItemWithNeedsDocs(item)}
              </span>
            </div>
          ))}
        </div>
      </div>
    ))}
  </div>
);

// ---------------------------------------------------------------------------
// Release row header (ID chip + version + date + badges)
// ---------------------------------------------------------------------------
const ReleaseHeader = ({ release, latestDate, showId }) => {
  const isLatest = release.date === latestDate;
  const vStats = {};
  if (release.changes) release.changes.forEach(c => { vStats[c.category] = c.items?.length ?? 0; });

  return (
    <div className="flex items-center justify-between w-full gap-3">
      <div className="flex items-center gap-2 min-w-0">
        {showId && (
          <span className="px-1.5 py-0.5 rounded border-2 border-green-500/60 text-green-400 text-[10px] font-bold uppercase flex-shrink-0">
            {release.id}
          </span>
        )}
        <span className="text-sm font-bold text-white flex-shrink-0">v{release.version}</span>
        <span className="text-[11px] text-gray-500 flex-shrink-0">{release.date}</span>
        {isLatest && (
          <span className="px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/30 text-green-400 text-[9px] font-bold uppercase flex-shrink-0">
            Latest
          </span>
        )}
      </div>
      <StatBadges stats={vStats} />
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
function ChangelogViewer({ versions, isPopup = false }) {
  const [activeTab, setActiveTab] = useState('ALL');

  if (!versions || versions.length === 0) {
    return <p className="text-sm text-gray-500 text-center py-8">No changelog data available.</p>;
  }

  const latestDate = useMemo(
    () => versions.reduce((latest, v) => (v.date > latest ? v.date : latest), versions[0].date),
    [versions],
  );

  const availableModules = useMemo(() => {
    const seen = new Map();
    versions.forEach(v => {
      const id = v.id || 'SYS';
      if (!seen.has(id)) seen.set(id, v.service || 'System Updates');
    });
    return Array.from(seen.entries()).map(([id, service]) => ({ id, service }));
  }, [versions]);

  const filteredVersions = useMemo(() => {
    if (isPopup || activeTab === 'ALL') return versions;
    return versions.filter(v => (v.id || 'SYS') === activeTab);
  }, [versions, activeTab, isPopup]);

  const categoryTotals = useMemo(() => {
    const totals = { total: 0, categories: {} };
    filteredVersions.forEach(v => {
      (v.changes || []).forEach(c => {
        const count = c.items?.length ?? 0;
        totals.total += count;
        totals.categories[c.category] = (totals.categories[c.category] || 0) + count;
      });
    });
    return totals;
  }, [filteredVersions]);

  const groupedByMonth = useMemo(() => {
    if (activeTab !== 'ALL' && !isPopup) return [];
    const groups = {};
    filteredVersions.forEach(v => {
      const [year, month] = v.date.split('-');
      const label = new Date(parseInt(year), parseInt(month) - 1)
        .toLocaleString('en-US', { month: 'long', year: 'numeric' })
        .toUpperCase();
      const sortKey = `${year}-${month}`;
      if (!groups[label]) groups[label] = { label, sortKey, releases: [], stats: {} };
      groups[label].releases.push(v);
      (v.changes || []).forEach(c => {
        const count = c.items?.length ?? 0;
        groups[label].stats[c.category] = (groups[label].stats[c.category] || 0) + count;
      });
    });
    return Object.values(groups).sort((a, b) => b.sortKey.localeCompare(a.sortKey));
  }, [filteredVersions, activeTab, isPopup]);

  const groupedByVersionFamily = useMemo(() => {
    if (activeTab === 'ALL' || isPopup) return [];
    const groups = {};
    filteredVersions.forEach(v => {
      const parts = v.version.split('.');
      const family = parts.length >= 2 ? `Version ${parts[0]}.${parts[1]}.x` : `Version ${v.version}`;
      if (!groups[family]) groups[family] = { family, releases: [], stats: {} };
      groups[family].releases.push(v);
      (v.changes || []).forEach(c => {
        const count = c.items?.length ?? 0;
        groups[family].stats[c.category] = (groups[family].stats[c.category] || 0) + count;
      });
    });
    return Object.values(groups);
  }, [filteredVersions, activeTab, isPopup]);

  const showId = activeTab === 'ALL' || isPopup;

  return (
    <div>
      {/* Module tabs — hidden in popup mode or when only one module */}
      {!isPopup && availableModules.length > 1 && (
        <div className="flex gap-1 border-b border-gray-800 mb-4 overflow-x-auto">
          {[{ id: 'ALL', service: 'All Updates' }, ...availableModules].map(mod => (
            <button
              key={mod.id}
              onClick={() => setActiveTab(mod.id)}
              title={mod.service}
              className={`px-4 py-2 text-xs font-bold uppercase tracking-wider whitespace-nowrap transition-colors border-b-2 -mb-px ${
                activeTab === mod.id
                  ? 'border-green-500 text-green-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              {mod.id === 'ALL' ? 'All Updates' : mod.id}
            </button>
          ))}
        </div>
      )}

      {/* Total delivery summary — hidden in popup mode */}
      {!isPopup && (
        <div className="mb-4 p-4 bg-gray-900 border border-gray-800 border-l-4 border-l-green-500 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <BarChart3 size={13} className="text-green-400" /> Total Delivery
            </div>
            <span className="px-2 py-0.5 rounded-full bg-green-600 text-black text-[10px] font-black">
              {categoryTotals.total} items
            </span>
          </div>
          <div className="flex flex-wrap gap-5">
            {Object.entries(categoryTotals.categories).map(([cat, count]) => {
              const icon = getCategoryIcon(cat);
              const text = cat.replace(/^[^\w\s]+/, '').trim();
              return (
                <div key={cat} className="flex items-center gap-2">
                  <span className="text-xl leading-none">{icon}</span>
                  <div>
                    <div className="text-[9px] text-gray-500 uppercase tracking-widest font-bold">{text}</div>
                    <div className="text-lg font-black text-white leading-none">{count}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Month-grouped view (ALL tab or popup) */}
      {(isPopup || activeTab === 'ALL') && groupedByMonth.map((group, gi) => (
        <Accordion
          key={group.label}
          defaultExpanded={gi === 0}
          header={
            <div className="flex items-center justify-between w-full gap-3">
              <span className="text-xs font-black text-white tracking-widest uppercase">{group.label}</span>
              <StatBadges stats={group.stats} />
            </div>
          }
        >
          {group.releases.map(release => (
            <Accordion
              key={`${release.id}-${release.version}`}
              nested
              defaultExpanded={release.date === latestDate}
              header={<ReleaseHeader release={release} latestDate={latestDate} showId={showId} />}
            >
              {renderChanges(release.changes)}
            </Accordion>
          ))}
        </Accordion>
      ))}

      {/* Version-family-grouped view (single module tab) */}
      {!isPopup && activeTab !== 'ALL' && groupedByVersionFamily.map((group, gi) => (
        <Accordion
          key={group.family}
          defaultExpanded={gi === 0}
          header={
            <div className="flex items-center justify-between w-full gap-3">
              <span className="text-sm font-bold text-white">{group.family}</span>
              <StatBadges stats={group.stats} />
            </div>
          }
        >
          {group.releases.map((release, ri) => (
            <Accordion
              key={release.version}
              nested
              defaultExpanded={gi === 0 && ri === 0}
              header={<ReleaseHeader release={release} latestDate={latestDate} showId={false} />}
            >
              {renderChanges(release.changes)}
            </Accordion>
          ))}
        </Accordion>
      ))}
    </div>
  );
}

export default ChangelogViewer;
