import React, { useState, useEffect, useRef, useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { Disc, Zap, Activity, Shield, Search, RefreshCw, Maximize2 } from 'lucide-react';

const THEME = {
  green: "#00D065",
  red: "#ef4444",
  orange: "#f97316",
  blue: "#3b82f6",
  purple: "#a855f7",
  black: "#050505",
  gray: "#1E1E1E"
};

const TrafficTorus = ({ data, onHostClick }) => {
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

  // 2. Torus Layout Logic
  const torusData = useMemo(() => {
    if (!data || !data.topology) return { nodes: [], links: [] };

    const R = 200; // Major radius (Distance from center of tube to center of torus)
    const r = 60;  // Minor radius (Radius of the tube)

    const nodes = data.topology.nodes.map((node, i) => {
      // Deterministic mapping to torus surface
      // Use index or hash of ID to spread nodes
      const hash = node.id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
      
      const theta = (hash % 100 / 100) * 2 * Math.PI; // Angle around the major ring
      const phi = ((hash / 100) % 100 / 100) * 2 * Math.PI;   // Angle around the tube

      const x = (R + r * Math.cos(phi)) * Math.cos(theta);
      const y = (R + r * Math.cos(phi)) * Math.sin(theta);
      const z = r * Math.sin(phi);

      return {
        ...node,
        fx: x, fy: y, fz: z, // Force positions to be static on the surface
        color: node.score > 5 ? THEME.red : node.score > 2 ? THEME.orange : node.is_internal ? THEME.blue : THEME.purple
      };
    });

    // Ribbons (Thick Links)
    const links = data.topology.links.map(link => ({
        ...link,
        width: Math.max(1, Math.log10(link.value + 1) * 2),
        color: (link.type === 'block') ? 'rgba(239, 68, 68, 0.4)' : 'rgba(59, 130, 246, 0.2)'
    }));

    return { nodes, links };
  }, [data]);

  return (
    <div className="flex flex-col h-full space-y-4 animate-in fade-in duration-700">
      {/* TORUS HEADER */}
      <div className="flex justify-between items-center bg-[#121212] p-4 rounded-lg border border-gray-800 shadow-xl">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-blue-500/10 rounded border border-blue-500/20 text-blue-400">
            <Disc size={24} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white uppercase tracking-wider flex items-center gap-2">
              Traffic Torus <Activity size={16} className="text-blue-500 animate-pulse" />
            </h2>
            <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest">
              High-Performance Planar Projection (Surface Mapping)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
            <div className="flex gap-4 text-[10px] uppercase font-bold text-gray-500">
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-blue-500 rounded-sm"></div> Internal</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-purple-500 rounded-sm"></div> External</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-red-500 rounded-sm"></div> Anomalous</div>
            </div>
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" size={14} />
                <input 
                    type="text" 
                    placeholder="Trace Flow..." 
                    className="bg-black border border-gray-800 rounded pl-9 pr-4 py-1.5 text-xs text-white focus:border-blue-500 outline-none w-48 transition-all focus:w-64"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>
            <button onClick={() => fgRef.current.zoomToFit(1000)} className="p-2 bg-gray-800 rounded border border-gray-700 hover:text-white transition-colors">
                <Maximize2 size={16} />
            </button>
        </div>
      </div>

      {/* THE TORUS VIEW */}
      <div className="flex-1 bg-[#050505] rounded-lg border border-gray-800 relative overflow-hidden" ref={containerRef}>
        <ForceGraph3D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={torusData}
          backgroundColor={THEME.black}
          
          // Node Styling
          nodeColor={n => n.color}
          nodeLabel={n => n.name || n.id}
          nodeRelSize={4}
          
          // Link Styling (Flow Ribbons)
          linkWidth={l => l.width}
          linkColor={l => l.color}
          linkDirectionalParticles={2}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleWidth={2}
          
          // Interaction
          onNodeHover={setHoverNode}
          onNodeClick={onHostClick}
          
          // Torus Surface "Skin" effect (Visual reference)
          onSceneMounted={scene => {
              const geometry = new THREE.TorusGeometry(200, 60, 32, 100);
              const material = new THREE.MeshBasicMaterial({ 
                  color: '#111', 
                  wireframe: true, 
                  transparent: true, 
                  opacity: 0.05 
              });
              const torus = new THREE.Mesh(geometry, material);
              scene.add(torus);
          }}
        />

        {/* OVERLAY TOOLTIP */}
        {hoverNode && (
            <div className="absolute top-4 left-4 z-50 bg-black/90 border border-blue-500/30 p-4 rounded shadow-2xl backdrop-blur-md animate-in zoom-in-95 duration-200 pointer-events-none">
                <div className="text-blue-400 font-black font-mono text-lg mb-1">{hoverNode.name || hoverNode.id}</div>
                <div className="text-[10px] text-gray-500 font-bold uppercase mb-3">{hoverNode.site_name || 'Torus Segment'}</div>
                
                <div className="grid grid-cols-2 gap-x-6 gap-y-4 mt-3">
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Health</div>
                        <div className={`text-xl font-black ${(hoverNode.score || 0) > 5 ? 'text-red-500' : 'text-green-500'}`}>
                            {Math.max(0, 100 - (hoverNode.score * 10)).toFixed(0)}%
                        </div>
                    </div>
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Connections</div>
                        <div className="text-sm font-bold text-white">
                            Active Flow
                        </div>
                    </div>
                </div>
            </div>
        )}

        {/* STATS */}
        <div className="absolute bottom-4 right-4 bg-black/80 border border-gray-800 p-3 rounded backdrop-blur text-[10px] font-bold text-gray-500 uppercase tracking-widest pointer-events-none flex gap-6">
            <div className="flex items-center gap-2">
                <Zap size={14} className="text-yellow-500" />
                <span>Surface Area Optimzed</span>
            </div>
            <span>Nodes: {torusData.nodes.length}</span>
        </div>
      </div>
    </div>
  );
};

export default TrafficTorus;
