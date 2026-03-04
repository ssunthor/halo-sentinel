import React, { useState, useEffect, useRef, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Box, Sparkles, Zap, ShieldAlert, Search, RefreshCw, Layers } from 'lucide-react';

const THEME = {
  green: "#00D065",
  red: "#ef4444",
  orange: "#f97316",
  blue: "#3b82f6",
  purple: "#a855f7",
  black: "#050505",
  gray: "#1E1E1E"
};

const BehavioralHive = ({ data, onHostClick }) => {
  const fgRef = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [searchTerm, setSearchTerm] = useState('');
  const [hoverNode, setHoverNode] = useState(null);

  // 1. Resize Handler
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      for (let entry of entries) {
        setDimensions({ width: entry.contentRect.width, height: entry.contentRect.height });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // 2. Data Transformation for the Hive
  // Instead of physical links, we create "Behavioral Clusters"
  const hiveData = useMemo(() => {
    if (!data || !data.topology || !data.topology.nodes) return { nodes: [], links: [] };

    const nodes = data.topology.nodes.map(node => {
      // Define behavioral coordinates (Simplified for now)
      // X: Traffic Volume, Y: Anomaly Score, Z: Security Intensity
      const volume = Math.log10((node.sent || 0) + (node.received || 0) + 1);
      const score = node.score || 0;
      
      // Determine Cluster (Group similar nodes)
      let cluster = 'standard';
      if (score > 5) cluster = 'anomalous';
      else if (volume > 6) cluster = 'high_volume';
      else if (node.category === 'Authentication') cluster = 'auth';
      
      return {
        ...node,
        volume,
        cluster,
        // Visual properties
        val: 4 + (volume * 0.5),
        color: score > 5 ? THEME.red : score > 2 ? THEME.orange : node.is_internal ? THEME.blue : THEME.purple
      };
    });

    // Create synthetic links based on cluster membership to pull them together
    const links = [];
    const clusterGroups = {};
    nodes.forEach(n => {
        if (!clusterGroups[n.cluster]) clusterGroups[n.cluster] = [];
        clusterGroups[n.cluster].push(n.id);
    });

    // Link each node to a "cluster center" (first node in group) to create clumps
    Object.values(clusterGroups).forEach(group => {
        const center = group[0];
        for (let i = 1; i < group.length; i++) {
            links.push({ source: center, target: group[i], value: 0.1 });
        }
    });

    return { nodes, links };
  }, [data]);

  // 3. Hexagon Drawing Logic
  const drawHexagon = (node, ctx, globalScale) => {
    const { x, y, val, color, score } = node;
    const size = val;
    
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i;
      const hx = x + size * Math.cos(angle);
      const hy = y + size * Math.sin(angle);
      if (i === 0) ctx.moveTo(hx, hy);
      else ctx.lineTo(hx, hy);
    }
    ctx.closePath();

    // Glitch / Pulse effect for high score
    if (score > 5) {
        const pulse = (Math.sin(Date.now() / 200) + 1) / 2;
        ctx.fillStyle = pulse > 0.5 ? THEME.red : '#ffffff';
        ctx.shadowBlur = 15 * pulse;
        ctx.shadowColor = THEME.red;
    } else {
        ctx.fillStyle = color;
        ctx.shadowBlur = 0;
    }
    
    ctx.fill();

    // Border
    ctx.strokeStyle = 'rgba(255,255,255,0.1)';
    ctx.lineWidth = 1 / globalScale;
    ctx.stroke();

    // Hover effect
    if (hoverNode === node) {
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
    }
  };

  return (
    <div className="flex flex-col h-full space-y-4 animate-in fade-in duration-700">
      {/* HIVE HEADER */}
      <div className="flex justify-between items-center bg-[#121212] p-4 rounded-lg border border-gray-800 shadow-xl">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-purple-500/10 rounded border border-purple-500/20 text-purple-400">
            <Box size={24} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white uppercase tracking-wider flex items-center gap-2">
              Behavioral Hive <Sparkles size={16} className="text-yellow-500 animate-pulse" />
            </h2>
            <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest">
              Dimensional Clustering by AI Pattern Recognition
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
            <div className="flex gap-4 text-[10px] uppercase font-bold text-gray-500">
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-red-500 rounded-sm"></div> Anomalous</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-blue-500 rounded-sm"></div> Internal</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-purple-500 rounded-sm"></div> External</div>
            </div>
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" size={14} />
                <input 
                    type="text" 
                    placeholder="Search Behavior..." 
                    className="bg-black border border-gray-800 rounded pl-9 pr-4 py-1.5 text-xs text-white focus:border-purple-500 outline-none w-48 transition-all focus:w-64"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>
            <button onClick={() => fgRef.current.zoomToFit(1000)} className="p-2 bg-gray-800 rounded border border-gray-700 hover:text-white transition-colors">
                <RefreshCw size={16} />
            </button>
        </div>
      </div>

      {/* THE HIVE GRID */}
      <div className="flex-1 bg-[#050505] rounded-lg border border-gray-800 relative overflow-hidden" ref={containerRef}>
        <ForceGraph2D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={hiveData}
          backgroundColor={THEME.black}
          nodeCanvasObject={drawHexagon}
          onNodeHover={setHoverNode}
          onNodeClick={onHostClick}
          
          // Force Configuration for "Clumping"
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.4}
          cooldownTicks={100}
        />

        {/* OVERLAY TOOLTIP */}
        {hoverNode && (
            <div className="absolute top-4 left-4 z-50 bg-black/90 border border-purple-500/30 p-4 rounded shadow-2xl backdrop-blur-md animate-in zoom-in-95 duration-200 pointer-events-none">
                <div className="text-purple-400 font-black font-mono text-lg mb-1">{hoverNode.name || hoverNode.id}</div>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 mt-3">
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Anomaly Score</div>
                        <div className={`text-sm font-black ${(hoverNode.score || 0) > 5 ? 'text-red-500' : 'text-white'}`}>
                            {(hoverNode.score || 0).toFixed(2)}
                        </div>
                    </div>
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Category</div>
                        <div className="text-sm font-bold text-white truncate max-w-[100px]">{hoverNode.category || 'Standard'}</div>
                    </div>
                    <div className="col-span-2 border-t border-gray-800 pt-2 mt-1">
                        <div className="text-[9px] uppercase text-gray-500 font-bold mb-1">Observed Ports</div>
                        <div className="flex flex-wrap gap-1">
                            {(hoverNode.ports || []).slice(0, 3).map(p => (
                                <span key={p} className="px-1.5 py-0.5 bg-purple-900/20 border border-purple-900/30 rounded text-[8px] text-purple-300 font-mono">{p}</span>
                            ))}
                            {(hoverNode.ports || []).length > 3 && <span className="text-[8px] text-gray-600">+{hoverNode.ports.length - 3} more</span>}
                        </div>
                    </div>
                </div>
                {hoverNode.reason && (
                    <div className="mt-3 p-2 bg-red-900/10 border border-red-900/20 rounded">
                        <div className="text-[8px] uppercase text-red-500 font-black mb-1">Behavioral Alert</div>
                        <div className="text-[10px] text-gray-300 italic">"{hoverNode.reason}"</div>
                    </div>
                )}
            </div>
        )}

        {/* HIVE STATS FLOATER */}
        <div className="absolute bottom-4 right-4 bg-black/80 border border-gray-800 p-3 rounded backdrop-blur text-[10px] font-bold text-gray-500 uppercase tracking-widest pointer-events-none flex gap-6">
            <div className="flex items-center gap-2">
                <Layers size={14} className="text-blue-500" />
                <span>Nodes: {hiveData.nodes.length}</span>
            </div>
            <div className="flex items-center gap-2">
                <Zap size={14} className="text-yellow-500" />
                <span>Throughput: {data.metrics.eps} EPS</span>
            </div>
        </div>
      </div>
    </div>
  );
};

export default BehavioralHive;
