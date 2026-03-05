import React, { useState, useEffect, useRef, useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import SpriteText from 'three-spritetext';
import { Building2, Zap, AlertTriangle, Shield, Search, RefreshCw, Layers } from 'lucide-react';

const THEME = {
  green: "#00D065",
  red: "#ef4444",
  orange: "#f97316",
  blue: "#3b82f6",
  purple: "#a855f7",
  black: "#050505",
  gray: "#1E1E1E"
};

const CyberCity = ({ data, onHostClick }) => {
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

  // 2. City Layout Logic (Group by Site into "Neighborhoods")
  const cityData = useMemo(() => {
    // Priority: Use 'all_hosts' list if available, fallback to topology nodes
    const sourceNodes = data?.all_hosts || data?.topology?.nodes || [];
    if (sourceNodes.length === 0) return { nodes: [], links: [] };

    // Group nodes by site
    const sites = {};
    sourceNodes.forEach(node => {
        const site = node.site_name || 'External';
        if (!sites[site]) sites[site] = [];
        sites[site].push(node);
    });

    const nodes = [];
    const siteKeys = Object.keys(sites);
    const gridSize = Math.ceil(Math.sqrt(siteKeys.length));
    const siteSpacing = 400; // Distance between neighborhoods
    const buildingSpacing = 40; // Distance between buildings in a neighborhood

    siteKeys.forEach((site, sIdx) => {
        const siteX = (sIdx % gridSize) * siteSpacing;
        const siteZ = Math.floor(sIdx / gridSize) * siteSpacing;
        
        const siteNodes = sites[site];
        const bGridSize = Math.ceil(Math.sqrt(siteNodes.length));

        siteNodes.forEach((node, bIdx) => {
            const bx = siteX + (bIdx % bGridSize) * buildingSpacing;
            const bz = siteZ + Math.floor(bIdx / bGridSize) * buildingSpacing;
            
            // Fallback to event count (val) if bytes are missing/zero
            const totalTraffic = (node.sent || 0) + (node.received || 0) + ((node.val || 0) * 1000); 
            const height = Math.max(5, Math.log10(totalTraffic + 1) * 15);
            const score = node.score || 0;

            nodes.push({
                ...node,
                fx: bx,
                fy: height / 2, // Sit on the "ground"
                fz: bz,
                buildingHeight: height,
                color: score > 5 ? THEME.red : score > 2 ? THEME.orange : node.is_internal ? THEME.blue : THEME.purple
            });
        });
    });

    return { nodes, links: [] }; // No links in city view to keep it clean
  }, [data]);

  // 3. Building Geometry Generator
  const createBuilding = (node) => {
    const group = new THREE.Group();

    // The Building (Box)
    const geometry = new THREE.BoxGeometry(15, node.buildingHeight, 15);
    const material = new THREE.MeshPhongMaterial({
        color: node.color,
        transparent: true,
        opacity: 0.8,
        emissive: node.color,
        emissiveIntensity: node.score > 2 ? 0.5 : 0.2
    });
    const cube = new THREE.Mesh(geometry, material);
    group.add(cube);

    // High Risk Beacon (Vertical Light Beam)
    if (node.score > 5) {
        const beaconGeo = new THREE.CylinderGeometry(2, 2, 1000, 8);
        const beaconMat = new THREE.MeshBasicMaterial({
            color: THEME.red,
            transparent: true,
            opacity: 0.3
        });
        const beacon = new THREE.Mesh(beaconGeo, beaconMat);
        beacon.position.y = 500; // Shoot up from building
        group.add(beacon);

        // Pulse logic could be added here in an animation loop
    }

    // Label (Only if zoomed in or search match)
    const isSearchMatch = searchTerm && (node.id.includes(searchTerm) || node.name?.includes(searchTerm));
    if (isSearchMatch || node.score > 5) {
        const sprite = new SpriteText(node.name || node.id);
        sprite.color = '#fff';
        sprite.textHeight = 8;
        sprite.position.y = (node.buildingHeight / 2) + 10;
        group.add(sprite);
    }

    return group;
  };

  return (
    <div className="flex flex-col h-full space-y-4 animate-in fade-in duration-700">
      {/* CITY HEADER */}
      <div className="flex justify-between items-center bg-[#121212] p-4 rounded-lg border border-gray-800 shadow-xl">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-blue-500/10 rounded border border-blue-500/20 text-blue-400">
            <Building2 size={24} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white uppercase tracking-wider flex items-center gap-2">
              Cyber City <Layers size={16} className="text-gray-500" />
            </h2>
            <p className="text-[10px] text-gray-500 uppercase font-bold tracking-widest">
              Spatial Asset Visualization (Height = Traffic, Color = Risk)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
            <div className="flex gap-4 text-[10px] uppercase font-bold text-gray-500">
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-red-500 rounded-sm"></div> Critical</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-blue-500 rounded-sm"></div> Data Center</div>
                <div className="flex items-center gap-1.5"><div className="w-2 h-2 bg-purple-500 rounded-sm"></div> External</div>
            </div>
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" size={14} />
                <input 
                    type="text" 
                    placeholder="Locate Asset..." 
                    className="bg-black border border-gray-800 rounded pl-9 pr-4 py-1.5 text-xs text-white focus:border-blue-500 outline-none w-48 transition-all focus:w-64"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>
            <button onClick={() => fgRef.current.zoomToFit(1000)} className="p-2 bg-gray-800 rounded border border-gray-700 hover:text-white transition-colors">
                <RefreshCw size={16} />
            </button>
        </div>
      </div>

      {/* THE CITY GRID */}
      <div className="flex-1 bg-[#050505] rounded-lg border border-gray-800 relative overflow-hidden" ref={containerRef}>
        <ForceGraph3D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={cityData}
          backgroundColor={THEME.black}
          nodeThreeObject={createBuilding}
          onNodeHover={setHoverNode}
          onNodeClick={onHostClick}
          
          // Environment Settings
          showNavInfo={true}
          enableNodeDrag={false} // Static city layout
          numDimensions={3}
        />

        {/* OVERLAY TOOLTIP */}
        {hoverNode && (
            <div className="absolute top-4 left-4 z-50 bg-black/90 border border-blue-500/30 p-4 rounded shadow-2xl backdrop-blur-md animate-in zoom-in-95 duration-200 pointer-events-none">
                <div className="text-blue-400 font-black font-mono text-lg mb-1">{hoverNode.name || hoverNode.id}</div>
                <div className="text-[10px] text-gray-500 font-bold uppercase mb-3">{hoverNode.site_name || 'Global Neighborhood'}</div>
                
                <div className="grid grid-cols-2 gap-x-6 gap-y-4 mt-3">
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Risk Score</div>
                        <div className={`text-xl font-black ${(hoverNode.score || 0) > 5 ? 'text-red-500' : 'text-white'}`}>
                            {(hoverNode.score || 0).toFixed(2)}
                        </div>
                    </div>
                    <div>
                        <div className="text-[9px] uppercase text-gray-500 font-bold">Throughput</div>
                        <div className="text-sm font-bold text-white">
                            {((hoverNode.sent + hoverNode.received) / 1024 / 1024).toFixed(2)} MB
                        </div>
                    </div>
                </div>
                {hoverNode.reason && (
                    <div className="mt-4 p-2 bg-red-900/10 border border-red-900/20 rounded">
                        <div className="text-[8px] uppercase text-red-500 font-black mb-1">Status Alert</div>
                        <div className="text-[10px] text-gray-300 italic">"{hoverNode.reason}"</div>
                    </div>
                )}
            </div>
        )}

        {/* CITY STATS */}
        <div className="absolute bottom-4 right-4 bg-black/80 border border-gray-800 p-3 rounded backdrop-blur text-[10px] font-bold text-gray-500 uppercase tracking-widest pointer-events-none flex gap-6">
            <div className="flex items-center gap-2">
                <Zap size={14} className="text-yellow-500" />
                <span>Sector Active</span>
            </div>
            <span>City Density: {cityData.nodes.length} Blocks</span>
        </div>
      </div>
    </div>
  );
};

export default CyberCity;
