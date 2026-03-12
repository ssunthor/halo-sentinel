import React, { useState, useMemo, useEffect } from 'react';
import { 
  Search, Server, Activity, Shield, Clock, ArrowUpRight, ArrowDownLeft, 
  ExternalLink, ChevronRight, X, Globe, Zap, BarChart2, Filter, Loader2, Sparkles
} from 'lucide-react';

const getAnomalyColor = (score) => {
  if (score < 3) return "#00D065"; // THEME.green
  if (score < 6) return "#f97316"; // THEME.orange
  return "#ef4444"; // THEME.red
};

const HostInventory = ({ data, onHostClick }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [restHosts, setRestHosts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch full inventory once on mount + periodic refresh
  useEffect(() => {
    const fetchHosts = async () => {
        try {
            const response = await fetch('/api/hosts');
            if (response.ok) {
                const hosts = await response.json();
                setRestHosts(hosts);
            }
        } catch (e) {
            console.error("Failed to fetch host inventory:", e);
        } finally {
            setIsLoading(false);
        }
    };

    fetchHosts();
    const interval = setInterval(fetchHosts, 30000); // 30s refresh for new hosts
    return () => clearInterval(interval);
  }, []);

  // Merge the static REST list with live scores/stats from the WebSocket topology nodes
  const hosts = useMemo(() => {
    // topology.nodes usually contains the 'active' set with latest decayed scores
    const liveNodes = new Map(data?.topology?.nodes?.map(n => [n.id, n]) || []);

    return restHosts.map(h => {
      const live = liveNodes.get(h.id);
      return {
        id: h.id,
        name: h.name || h.id,
        // Prioritize live score from websocket, fallback to REST snapshot
        score: live ? live.score : h.score || 0,
        lastSeen: live ? (live.last_seen ? new Date(live.last_seen * 1000).toLocaleString() : 'Live') : (h.last_seen ? new Date(h.last_seen * 1000).toLocaleString() : 'Recent'),
        type: h.type || 'unknown',
        site: h.site_name || 'Global',
        isDfp: h.sources ? (h.sources.includes('netflow_v9') || h.sources.includes('netflow')) : false,
        sources: h.sources || [],
        total_events: live ? live.total_events : h.total_events || 0,
        security_events: live ? live.security_events : h.security_events || 0,
        category: h.category,
        reason: live ? (live.reason || h.reason) : h.reason,
        is_internal: h.is_internal,
        has_analysis: live ? live.has_analysis : h.has_analysis,
        isC2: (live ? (live.reason || h.reason) : h.reason) === "C2 Server Communication"
      };
    }).sort((a, b) => {
      // 1. C2 ALWAYS at top
      if (a.isC2 && !b.isC2) return -1;
      if (!a.isC2 && b.isC2) return 1;
      // 2. Then by score
      return b.score - a.score;
    });
  }, [restHosts, data]);

  const SourceBadge = ({ sources }) => {
    const hasLogs = sources.includes('syslog');
    const hasNetflow = sources.includes('netflow_v9') || sources.includes('netflow');
    
    return (
      <div className="flex gap-1">
        {hasLogs && (
          <span className="px-1.5 py-0.5 rounded-sm bg-blue-500/10 border border-blue-500/20 text-[9px] text-blue-400 font-bold uppercase">Logs</span>
        )}
        {hasNetflow && (
          <span className="px-1.5 py-0.5 rounded-sm bg-purple-500/10 border border-purple-500/20 text-[9px] text-purple-400 font-bold uppercase">Netflow</span>
        )}
      </div>
    );
  };

  const filteredHosts = hosts.filter(h => 
    (h.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
     h.name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const stats = useMemo(() => {
    return {
        total: hosts.length,
        critical: hosts.filter(h => h.score >= 3 || h.isC2).length,
        healthy: hosts.filter(h => h.score < 3 && !h.isC2).length
    };
  }, [hosts]);

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* SUMMARY STATS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#121212] border border-gray-800 p-4 rounded-lg shadow-lg flex items-center justify-between">
              <div>
                  <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Total Assets</p>
                  <p className="text-2xl font-black text-white">{stats.total}</p>
              </div>
              <Server className="text-blue-500 opacity-20" size={32} />
          </div>
          <div className="bg-[#121212] border border-red-900/30 p-4 rounded-lg shadow-lg flex items-center justify-between">
              <div>
                  <p className="text-[10px] font-bold text-red-500/70 uppercase tracking-widest">High Risk (≥ 3.0)</p>
                  <p className="text-2xl font-black text-red-500">{stats.critical}</p>
              </div>
              <Shield className="text-red-500 opacity-20" size={32} />
          </div>
          <div className="bg-[#121212] border border-green-900/30 p-4 rounded-lg shadow-lg flex items-center justify-between">
              <div>
                  <p className="text-[10px] font-bold text-green-500/70 uppercase tracking-widest">Healthy/Low Risk (&lt; 3.0)</p>
                  <p className="text-2xl font-black text-green-500">{stats.healthy}</p>
              </div>
              <Activity className="text-green-500 opacity-20" size={32} />
          </div>
      </div>

      {/* HEADER & FILTERS */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#121212] p-5 rounded-lg border border-gray-800 shadow-lg">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="text-blue-500" /> Host Inventory
          </h2>
          <p className="text-xs text-gray-500 mt-1">Managed assets and monitored network nodes (DFP Active)</p>
        </div>
        
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
            <input 
              type="text" 
              placeholder="Search by IP or Hostname..." 
              className="w-full bg-black border border-gray-800 rounded-md pl-10 pr-4 py-2 text-sm text-white focus:border-blue-500 focus:outline-none transition-all"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* HOST LIST TABLE */}
      <div className="bg-[#121212] border border-gray-800 rounded-lg overflow-hidden shadow-xl min-h-[400px] flex flex-col">
        {isLoading && hosts.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-gray-500 gap-3">
            <Loader2 size={40} className="animate-spin text-blue-500" />
            <span>Synchronizing Host Registry...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-[#0a0a0a] text-gray-500 uppercase text-[10px] font-bold tracking-widest border-b border-gray-800">
                <tr>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Host Details</th>
                  <th className="px-6 py-4">Source</th>
                  <th className="px-6 py-4">Location</th>
                  <th className="px-6 py-4 text-center">DFP Score</th>
                  <th className="px-6 py-4">Last Activity</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredHosts.map((host) => (
                  <tr 
                    key={host.id} 
                    className="hover:bg-gray-800/30 transition-colors cursor-pointer group"
                    onClick={() => onHostClick(host)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${host.score >= 6 ? 'bg-red-500 animate-pulse' : host.score >= 3 ? 'bg-orange-500' : 'bg-green-500'}`}></div>
                        <span className="text-[10px] font-bold text-gray-500 uppercase">{host.score >= 6 ? 'Critical' : host.score >= 3 ? 'Warning' : 'Healthy'}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <div className="flex items-center gap-2">
                            <span className="font-bold text-white group-hover:text-blue-400 transition-colors">{host.name}</span>
                            {host.isC2 && (
                                <span className="px-1.5 py-0.5 rounded bg-red-900/40 border border-red-500 text-[8px] text-red-400 font-black uppercase animate-pulse">
                                    C2 Detected
                                </span>
                            )}
                            {host.has_analysis && <Sparkles size={14} className="text-purple-400 animate-pulse" title="AI Analysis Available" />}
                        </div>
                        <span className="text-xs text-gray-500 font-mono">{host.id}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <SourceBadge sources={host.sources} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 text-gray-400">
                        <Globe size={14} className="text-gray-600" />
                        <span>{host.site}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <div className="inline-flex items-center px-2 py-1 rounded bg-black/50 border border-gray-800">
                         <span className="font-mono font-bold" style={{ color: getAnomalyColor(host.score) }}>
                           {host.score.toFixed(2)}
                         </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <Clock size={12} />
                        {host.lastSeen}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="p-1.5 rounded hover:bg-blue-500/10 text-gray-500 hover:text-blue-400 transition-all">
                        <ExternalLink size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredHosts.length === 0 && (
                  <tr>
                    <td colSpan="6" className="px-6 py-20 text-center">
                      <div className="flex flex-col items-center gap-3 opacity-20">
                        <Server size={48} />
                        <span className="text-lg">No hosts found matching your search</span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default HostInventory;
