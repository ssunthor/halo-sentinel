import React, { useState, useEffect, useMemo, useRef, useLayoutEffect } from 'react';
import { 
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  ScatterChart, Scatter, ZAxis
} from 'recharts';
import { 
  Shield, Activity, Lock, Users, Globe as GlobeIcon, Terminal, 
  Server, Network, AlertTriangle, Map as MapIcon, Settings, 
  ChevronRight, ChevronLeft, ChevronDown, Monitor, Clock, Filter, Search, X, ShieldAlert, ShieldCheck,
  Play, Pause, ArrowRight, Ban, FileText, MousePointerClick, PieChart as PieIcon, BarChart2, Zap, Share2,
  Fingerprint, Info, RefreshCw, Orbit, Aperture, Sparkles,
  ArrowUpRight, ArrowDownLeft, ExternalLink, Download, Box, Building2, Disc, History
} from 'lucide-react';
import Globe from 'react-globe.gl';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup, Line } from "react-simple-maps";
import ForceGraph3D from 'react-force-graph-3d'; 
import ForceGraph2D from 'react-force-graph-2d';
import SpriteText from 'three-spritetext';
import * as THREE from 'three';
import RssFeed from './components/RssFeed';
import CveFeed from './components/CveFeed';
import NetboxVulnerabilities from './components/NetboxVulnerabilities';
import OverallAnalysis from './components/OverallAnalysis';
import HostInventory from './components/HostInventory';
import BehavioralHive from './components/BehavioralHive';
import CyberCity from './components/CyberCity';
import TrafficTorus from './components/TrafficTorus';
import ChatWidget from './components/ChatWidget';
import { DEFAULT_FEEDS } from './config/feeds';


// --- CONFIGURATION ---
const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// --- COUNTDOWN TIMER COMPONENT ---
const CountdownTimer = ({ targetTimestamp }) => {
  const [timeLeft, setTimeLeft] = useState(0);

  useEffect(() => {
    if (!targetTimestamp) return;
    
    const interval = setInterval(() => {
      const now = Date.now() / 1000;
      const diff = Math.max(0, targetTimestamp - now);
      setTimeLeft(diff);
    }, 1000);
    
    return () => clearInterval(interval);
  }, [targetTimestamp]);

  const minutes = Math.floor(timeLeft / 60);
  const seconds = Math.floor(timeLeft % 60);
  return (
    <span className="font-mono text-gray-400">
      {minutes}:{seconds.toString().padStart(2, '0')}
    </span>
  );
};

// --- THEME CONFIGURATION ---
const THEME = {
  green: "#00D065",
  black: "#000000",
  darkGray: "#121212",
  gray: "#1E1E1E",
  text: "#E0E0E0",
  red: "#ef4444",
  orange: "#f97316",
  blue: "#3b82f6"
};

// --- COLOR PALETTE FOR CHARTS ---
const COLORS = {
  security: THEME.orange,
  auth_fail: THEME.red,
  logons: THEME.green,
  sudo: THEME.blue,
  root: "#a855f7",
  firewall_block: "#eab308",
  other: "#6b7280"
};

// --- USERNAME BLACKLIST ---
const INVALID_USERS = new Set([
  'slice', 'manager', 'target', 'service', 'daemon', 'process', 'system', 
  'unknown', 'failed', 'error', 'start', 'stop', 'reached', 'listening',
  'dependency', 'socket', 'path', 'timer', 'swap', 'device', 'mount', 'automount',
  'session', 'scope', 'unit', 'job', 'start', 'result', 'done', 'starting', 'stopped',
  'message', 'runtime', 'application', 'with', 'successful', 'input', 'none', 'username',
  'audit', 'login', 'logout', 'authenticated', 'disconnected'
]);

// --- CIDR FILTER HELPER (192.168.0.0/27) ---
const isInTargetSubnet = (ip) => {
  if (!ip) return false;
  // fast check for 192.168.0.x prefix
  if (!ip.startsWith("192.168.0.")) return false;
  
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  
  // Check the last octet for /27 (0-31)
  const lastOctet = parseInt(parts[3], 10);
  return lastOctet >= 0 && lastOctet <= 31;
};


class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4 bg-red-900/20 border border-red-500 rounded text-red-500 h-full flex flex-col items-center justify-center">
          <AlertTriangle size={48} className="mb-4" />
          <h2 className="text-lg font-bold">Widget Crash</h2>
          <pre className="text-xs mt-2 opacity-75">{this.state.error.toString()}</pre>
          <button 
            onClick={() => this.setState({ hasError: false })}
            className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-500"
          >
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
// --- DATA NORMALIZATION HELPER ---
const normalizeLog = (rawLog) => {
    let category = "other";
    let is_sec = false;
    
    // Prioritize backend-assigned category
    if (rawLog.category) {
        category = rawLog.category;
    } else if (rawLog.event_type_str && rawLog.event_type_str !== "unknown") {
        category = rawLog.event_type_str;
    } else if (rawLog.main_label) {
        const label = rawLog.main_label.toUpperCase();
        if (label.includes("AUTHENTICATION_SUCCESS")){
          category = "logon";
          is_sec = true;
        }
        else if (label.includes("AUTHENTICATION_FAILURE")){
          category = "auth_fail";
          is_sec = true;
        } 
        else if (label.includes("FIREWALL") || label.includes("BLOCK")){ 
		category = "firewall_block";
		is_sec = true;
	}
        else if (label.includes("SUDO")){
          category = "sudo";
          is_sec = true;
        }
        else if (label.includes("NON_SECURITY") || label.includes("NORMAL")){
		category = "system";
		is_sec = false
	}
        else if (label.includes("SECURITY")){
          category = "security";
          is_sec = true;
        }
        else if (label.includes("DNS")) category = "dns";
    } else if (rawLog.category) {
        category = rawLog.category;
    }

    let priority = "low";
    if (rawLog.priority_str && rawLog.priority_str !== "unknown") {
         priority = rawLog.priority_str.toLowerCase();
    } else if (rawLog.priority) {
         priority = rawLog.priority <= 3 ? "critical" : rawLog.priority <= 5 ? "high" : "low";
    }

    let timeStr = "--:--:--";
    if (rawLog.time) {
        timeStr = rawLog.time;
    } else if (rawLog.timestamp) {
        const date = new Date(rawLog.timestamp);
        timeStr = date.toLocaleTimeString('en-US', { hour12: false });
    } else if (rawLog.syslog_timestamp) {
        timeStr = rawLog.syslog_timestamp;
    }

    const host = rawLog.source || rawLog.host || "unknown";
    
    return {
        ...rawLog,
        category, 
        priority, 
        time: timeStr,
        host,
        user: sanitizeUser(rawLog.user) || 'unknown',
        msg: rawLog.message || rawLog.msg,
        anomaly_score: typeof rawLog.anomaly_score === 'number' ? rawLog.anomaly_score : -1,
        mean_abs_err: typeof rawLog.mean_abs_err === 'number' ? rawLog.mean_abs_err : -1,
        is_sec: rawLog.is_security_event === true
        //: rawLog.is_security_event === true
    };
};

const sanitizeUser = (rawUser) => {
  if (!rawUser) return null;
  let user = rawUser.trim().replace(/[.:;]+$/, '');
  if (user.includes(' ')) return null; 
  if (user.length < 2) return null;     
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(user)) return null; 
  if (INVALID_USERS.has(user.toLowerCase())) return null;
  return user;
};

const getLogSignature = (log) => {
  if (log.uuid) return log.uuid;
  if (log.id) return log.id;
  return `${log.time}-${log.host}-${log.msg}-${log.priority}`;
};

const parseFirewallData = (msg) => {
  if (!msg) return { srcIp: '-', dstIp: '-', srcPort: '', dstPort: '', proto: '-', action: '-', acPolicy: '-', ruleName: '-' };
  
  // UPDATED REGEX: 
  // 1. \s*:\s* handles spaces around the colon (SrcIP : 1.2.3.4)
  // 2. [a-fA-F0-9\.:]+ matches IPv4 AND IPv6
  const srcIp = (msg.match(/SrcIP\s*:\s*([a-fA-F0-9\.:]+)/i) || [])[1] || '-';
  const dstIp = (msg.match(/DstIP\s*:\s*([a-fA-F0-9\.:]+)/i) || [])[1] || '-';
  
  const srcPort = (msg.match(/SrcPort\s*:\s*(\d+)/i) || [])[1] || '';
  const dstPort = (msg.match(/DstPort\s*:\s*(\d+)/i) || [])[1] || '';
  const proto = (msg.match(/Protocol\s*:\s*(\w+)/i) || [])[1] || 'TCP';
  
  // Handle different FTD/ASA formats for Action
  const action = (msg.match(/AccessControlRuleAction\s*:\s*(\w+)/i) || [])[1] || 'Block';
  
  const acPolicy = (msg.match(/ACPolicy\s*:\s*([^,]+)/i) || [])[1] || '-';
  const ruleName = (msg.match(/AccessControlRuleName\s*:\s*([^,]+)/i) || [])[1] || '-';
  
  return { srcIp, dstIp, srcPort, dstPort, proto, action, acPolicy, ruleName };
};

const getAnomalyColor = (score) => {
  if (score <= 2) return THEME.green;
  if (score <= 5) return THEME.orange;
  return THEME.red;
};

// --- COMPONENT: NETFLOW GALAXY (Host -> Port Topology) ---
const NetflowGalaxy = ({ data }) => {
  const fgRef = useRef();
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  useEffect(() => {
    if (!data || data.length === 0) return;

    const nodes = new Map();
    const links = new Map();

    data.forEach(flow => {
      // 1. Create Source Node (The Host)
      if (!nodes.has(flow.host)) {
        nodes.set(flow.host, { 
          id: flow.host, 
          group: 'host', 
          val: 10, // Size
          color: '#3b82f6' // Blue
        });
      }

      // 2. Create Target Node (The Port)
      const portId = `port-${flow.port}`;
      if (!nodes.has(portId)) {
        nodes.set(portId, { 
          id: portId, 
          name: `${flow.port}`, // Label
          group: 'port', 
          val: 5, 
          color: '#6b7280' // Gray default
        });
      }

      // 3. Create/Update Link
      const linkId = `${flow.host}-${portId}`;
      const existingLink = links.get(linkId);

      // We want the link to reflect the MAX anomaly score seen for this pair
      // and the MAX byte size (to size the particle)
      const currentScore = flow.y || 0;
      const currentBytes = flow.bytes || 0;

      if (existingLink) {
        existingLink.maxScore = Math.max(existingLink.maxScore, currentScore);
        existingLink.maxBytes = Math.max(existingLink.maxBytes, currentBytes);
      } else {
        links.set(linkId, {
          source: flow.host,
          target: portId,
          maxScore: currentScore,
          maxBytes: currentBytes,
          val: 1
        });
      }
      
      // Update Port Node Color if it's involved in high anomaly activity
      if (currentScore > 5) {
        const portNode = nodes.get(portId);
        portNode.color = '#ef4444'; // Turn port Red
        portNode.val = 15; // Make it bigger
      }
    });

    setGraphData({
      nodes: Array.from(nodes.values()),
      links: Array.from(links.values())
    });

  }, [data]);

  // Physics Engine Settings
  useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge').strength(-100);
      fgRef.current.d3Force('link').distance(100);
    }
  }, []);

  return (
    <div className="h-full w-full bg-[#050505] rounded-lg overflow-hidden border border-gray-800 relative">
       <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <div className="bg-black/80 p-2 rounded border border-gray-700 backdrop-blur">
          <h3 className="text-sm font-bold text-gray-200 flex items-center gap-2">
            <Orbit size={16} className="text-blue-500"/> Netflow Galaxy
          </h3>
          <div className="text-[10px] text-gray-500">
             Mapping 192.168.0.0/27 - Destination Ports
          </div>
        </div>
      </div>

      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        backgroundColor="#050505"
        
        // Node Styling
        nodeColor={node => node.color}
        nodeLabel={node => node.group === 'port' ? `Port ${node.name}` : node.id}
        nodeRelSize={4}
        
        // Render Text Labels for Ports
        nodeCanvasObject={(node, ctx, globalScale) => {
          const label = node.name || '';
          const fontSize = 12/globalScale;
          
          // Draw Node Circle
          ctx.beginPath(); 
          ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
          ctx.fillStyle = node.color;
          ctx.fill();

          // Draw Port Number Label
          if (node.group === 'port') {
            ctx.font = `${fontSize}px Sans-Serif`;
            ctx.textAlign = 'center'; 
            ctx.textBaseline = 'middle';
            ctx.fillStyle = 'white';
            ctx.fillText(label, node.x, node.y);
          }
        }}

        // Link Styling
        linkColor={link => link.maxScore > 5 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(255, 255, 255, 0.1)'}
        linkWidth={link => link.maxScore > 5 ? 2 : 1}
        linkCurvature={0.2}

        // Particle System (The Data Flow)
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.005}
        // Particle Size based on Bytes (Logarithmic scale to keep it sane)
        linkDirectionalParticleWidth={link => Math.max(1, Math.log10(link.maxBytes || 1))}
        linkDirectionalParticleColor={link => link.maxScore > 5 ? '#ef4444' : '#ffffff'}
      />
    </div>
  );
};

// --- COMPONENT: NETWORK galaxy (Final: Search, Physics, & Resize Fixed) ---
const Networkgalaxy = ({ data, onNodeClick, showExternal, setShowExternal, performanceMode, setPerformanceMode }) => {
  const containerRef = useRef(null);
  const fgRef = useRef();
  
  // --- STATE ---
  const [isPaused, setIsPaused] = useState(false);
  const [showLabels, setShowLabels] = useState(false); 
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState('2D'); // '2D' or '3D'
  const [showWireframe, setShowWireframe] = useState(false);
  const [tooltipNode, setTooltipNode] = useState(null);
  const [hoverPos, setHoverPos] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState(null);
  
  // DEFAULT DIMENSIONS (Fallback to prevent 0x0)
  const [dimensions, setDimensions] = useState({ 
      width: window.innerWidth > 0 ? window.innerWidth / 2 : 800, 
      height: window.innerHeight > 0 ? window.innerHeight / 2 : 600 
  });
  
  const [selectedDc, setSelectedDc] = useState('all');
  const [availableSites, setAvailableSites] = useState([]);
  const [showAllowed, setShowAllowed] = useState(true); 
  const [showBlocked, setShowBlocked] = useState(true); 
  const [expansion, setExpansion] = useState(1.0); // Expansion factor (1.0 = default)

  const nodesById = useRef(new Map());
  const linksById = useRef(new Map());
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  // 1. RESIZE OBSERVER
  useLayoutEffect(() => {
      if (!containerRef.current) return;
      const resizeObserver = new ResizeObserver((entries) => {
          for (let entry of entries) {
              const { width, height } = entry.contentRect;
              if (width > 0 && height > 0) {
                  setDimensions({ width, height });
              }
          }
      });
      resizeObserver.observe(containerRef.current);
      return () => resizeObserver.disconnect();
  }, []);

  // 2. SITE DISCOVERY
  useEffect(() => {
    if (!data || !data.nodes) return;
    const sites = new Map();
    data.nodes.forEach(node => {
        if (node.site && node.site_name) sites.set(node.site, node.site_name);
    });
    setAvailableSites(Array.from(sites.entries()).map(([slug, name]) => ({ slug, name })).sort((a, b) => a.name.localeCompare(b.name)));
  }, [data]);

  // 3. PHYSICS ENGINE (Logarithmic Scaling)
  useEffect(() => {
    if (fgRef.current) {
      const forceEngine = fgRef.current.d3Force;
      
      // Scale charge strength and distance by expansion factor
      forceEngine('charge')
        .strength(-300 * expansion)      
        .distanceMax(200 * expansion);   
      
      forceEngine('link')
        .distance(link => {
            const sVal = Math.max(link.source.val || 1, 1);
            const tVal = Math.max(link.target.val || 1, 1);
            // Scale base distance and logarithmic component by expansion
            return (30 + (Math.log(sVal) + Math.log(tVal)) * 10) * expansion; 
        })
        .strength(0.8);

      // Disable centering force when a node is selected to prevent the subgraph from flying to the middle
      forceEngine('center').strength(selectedNode ? 0 : 0.15); 
      
      // Reheat simulation so it reacts to slider
      fgRef.current.d3ReheatSimulation();
    }
  }, [viewMode, selectedNode, expansion]);

  // 4. HANDLERS
  const togglePause = () => {
    const nextPaused = !isPaused;
    setIsPaused(nextPaused);

    setGraphData(prevData => {
        const updatedNodes = prevData.nodes.map(node => {
            if (nextPaused) return { ...node, fx: node.x, fy: node.y }; // Lock
            else return { ...node, fx: null, fy: null }; // Release
        });
        return { ...prevData, nodes: updatedNodes };
    });
    
    if (!nextPaused && fgRef.current) fgRef.current.d3ReheatSimulation();
  };

  const handleRecenter = () => { if (fgRef.current) fgRef.current.zoomToFit(1000, 50); };
  const handleBackgroundClick = () => { setSelectedNode(null); };

  // --- PERFORMANCE OPTIMIZATION: Pre-calculate active set ---
  const activeIds = useMemo(() => {
      if (!selectedNode) return null;
      
      const nodeIds = new Set([selectedNode.id]);
      const linkIds = new Set();
      
      graphData.links.forEach(link => {
          const srcId = typeof link.source === 'object' ? link.source.id : link.source;
          const dstId = typeof link.target === 'object' ? link.target.id : link.target;
          
          if (srcId === selectedNode.id || dstId === selectedNode.id) {
              nodeIds.add(srcId);
              nodeIds.add(dstId);
              // Store link identity (reference or id if available, here we use the object itself logic in the render loop)
              // Actually, simpler to just check ends in the loop if the node check is fast.
              // But let's verify if we need link IDs. 
              // We can just check `activeIds.has(src) && activeIds.has(dst)`? 
              // No, that highlights links between neighbors too (triangles).
              // We ONLY want radial links from selectedNode.
          }
      });
      return nodeIds;
  }, [selectedNode, graphData]);

  const getNeighbors = (node) => {
      const neighbors = [];
      graphData.links.forEach(link => {
          const srcId = typeof link.source === 'object' ? link.source.id : link.source;
          const dstId = typeof link.target === 'object' ? link.target.id : link.target;
          if (srcId === node.id) neighbors.push(dstId);
          else if (dstId === node.id) neighbors.push(srcId);
      });
      return [...new Set(neighbors)].slice(0, 10); // Limit to 10
  };

  // 5. PAINT ENGINE (Crash Proof) - RESTORED FOR 2D
  const paintNode = React.useCallback((node, ctx, globalScale) => {
    if (node.x === undefined || node.y === undefined || Number.isNaN(node.x) || Number.isNaN(node.y)) return;

    // REVERTED: Using fixed radius instead of scaling by val/bandwidth
    const baseRadius = 3; 
    
    let color = THEME.blue; 
    let glowColor = 'rgba(59, 130, 246, 0.3)';

    if (node.score > 5) { color = THEME.red; glowColor = 'rgba(239, 68, 68, 0.5)'; } 
    else if (node.score > 2) { color = THEME.orange; glowColor = 'rgba(249, 115, 22, 0.5)'; }
    else if (node.type === 'src') { color = THEME.green; glowColor = 'rgba(0, 208, 101, 0.3)'; }

    // Glow
    if (node.score > 0 || globalScale > 1.5) {
        const glowRadius = baseRadius * (1.5 + Math.sin(Date.now() / 400) * 0.2);
        if (Number.isFinite(glowRadius)) {
            const gradient = ctx.createRadialGradient(node.x, node.y, baseRadius, node.x, node.y, glowRadius + 5);
            gradient.addColorStop(0, glowColor);
            gradient.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.beginPath(); ctx.arc(node.x, node.y, glowRadius + 5, 0, 2 * Math.PI, false); ctx.fillStyle = gradient; ctx.fill();
        }
    }

    // Body
    ctx.beginPath(); ctx.arc(node.x, node.y, baseRadius, 0, 2 * Math.PI, false); ctx.fillStyle = color; ctx.fill();
    
    // Ring
    if (node.val > 10) {
        ctx.beginPath(); ctx.arc(node.x, node.y, baseRadius + 2, 0, 2 * Math.PI, false); ctx.strokeStyle = color; ctx.lineWidth = 0.5; ctx.stroke();
    }
    
    // Labels
    const isTarget = node.id.toLowerCase().includes(searchTerm.toLowerCase()) && searchTerm.length > 1;
    if (showLabels || globalScale > 2.5 || node.score > 2 || isTarget) {
      const label = node.name || node.id;
      const fontSize = isTarget ? 14 / globalScale : 10 / globalScale; 
      
      if (Number.isFinite(fontSize)) {
        ctx.font = `${isTarget ? 'bold' : ''} ${fontSize}px Sans-Serif`;
        ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = 'rgba(0, 0, 0, 0.7)'; ctx.fillRect(node.x - textWidth / 2 - 2, node.y + baseRadius + 2, textWidth + 4, fontSize + 2);
        ctx.fillStyle = node.score > 5 ? '#ffaaaa' : '#e0e0e0'; ctx.fillText(label, node.x, node.y + baseRadius + 2);
      }
    }
  }, [showLabels, searchTerm]); 

  // 6. DATA PROCESSING
  useEffect(() => {
    if (!data) return;

    let activeLinks = data.links.filter(l => {
        if (l.type === 'block' && !showBlocked) return false;
        if ((l.type !== 'block') && !showAllowed) return false; 
        return true;
    });

    if (selectedDc !== 'all') {
        const dcNodeIds = new Set(data.nodes.filter(n => n.site === selectedDc).map(n => n.id));
        activeLinks = activeLinks.filter(l => dcNodeIds.has(l.source) || dcNodeIds.has(l.target));
    }

    if (searchTerm.trim() !== '') {
        const term = searchTerm.toLowerCase();
        const matchingIds = new Set(
            data.nodes.filter(n => n.id.toLowerCase().includes(term) || (n.name && n.name.toLowerCase().includes(term)))
            .map(n => n.id)
        );
        activeLinks = activeLinks.filter(l => matchingIds.has(l.source) || matchingIds.has(l.target));
    }

    const visibleNodeIds = new Set();
    
    // --- FILTER EXTERNAL NOISE ---
    let galaxyNodes = data.nodes;
    if (!showExternal) {
        // Only keep internal nodes or nodes with some anomaly score
        galaxyNodes = data.nodes.filter(n => n.is_internal || (n.score && n.score > 0));
    }
    
    // Links must connect visible nodes
    const validIds = new Set(galaxyNodes.map(n => n.id));
    activeLinks = activeLinks.filter(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return validIds.has(s) && validIds.has(t);
    });

    // --- SELECTION FILTERING ---
    if (selectedNode) {
        const sid = selectedNode.id;
        activeLinks = activeLinks.filter(l => {
            const s = typeof l.source === 'object' ? l.source.id : l.source;
            const t = typeof l.target === 'object' ? l.target.id : l.target;
            return s === sid || t === sid;
        });
    }

    activeLinks.forEach(l => { visibleNodeIds.add(l.source); visibleNodeIds.add(l.target); });
    const visibleNodesRaw = galaxyNodes.filter(n => visibleNodeIds.has(n.id));

    const newNodes = []; const currentIds = new Set();
    visibleNodesRaw.forEach(node => {
      currentIds.add(node.id);
      if (nodesById.current.has(node.id)) {
        const existing = nodesById.current.get(node.id);
        // Update values while preserving identity for physics stability
        existing.val = node.val; 
        existing.score = node.score;
        existing.type = node.type;
        existing.name = node.name;
        existing.site = node.site;
        existing.site_name = node.site_name;

        // STABILIZATION FIX: Lock positions if paused OR if focused (to stop subgraph reshuffling)
        if (isPaused || selectedNode) { 
            existing.fx = existing.x; 
            existing.fy = existing.y;
            if (existing.z) existing.fz = existing.z; // For 3D stability
        } else { 
            existing.fx = null; 
            existing.fy = null;
            existing.fz = null;
        }
        newNodes.push(existing);
      } else {
        const newNode = { ...node }; nodesById.current.set(node.id, newNode); newNodes.push(newNode);
      }
    });
    for (const id of nodesById.current.keys()) { if (!currentIds.has(id)) nodesById.current.delete(id); }

    const newLinks = []; const currentLinkIds = new Set();
    activeLinks.forEach(link => {
      const linkKey = `${link.source}-${link.target}`;
      currentLinkIds.add(linkKey);
      if (linksById.current.has(linkKey)) newLinks.push(linksById.current.get(linkKey));
      else { const newLink = { ...link }; linksById.current.set(linkKey, newLink); newLinks.push(newLink); }
    });
    for (const id of linksById.current.keys()) { if (!currentLinkIds.has(id)) linksById.current.delete(id); }

    setGraphData({ nodes: newNodes, links: newLinks });
  }, [data]);

  return (
    <div 
        className="h-full w-full bg-[#050505] rounded-lg overflow-hidden border border-gray-800 relative" 
        ref={containerRef}
        onMouseMove={(e) => {
            const rect = containerRef.current.getBoundingClientRect();
            setHoverPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
        }}
    >
      
      {/* HEADER */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <div className="bg-black/80 p-2 rounded border border-gray-700 backdrop-blur">
          <h3 className="text-sm font-bold text-gray-200 flex items-center gap-2">
            <Orbit size={16} className="text-green-500"/> {/* Icon Updated */}
            GTT Galaxy
          </h3>
          <div className="text-[10px] text-gray-500">
              Nodes: {graphData.nodes.length} | Links: {graphData.links.length}
          </div>
        </div>
      </div>

      {/* CONTROLS */}
      <div className="absolute top-4 right-4 z-10 pointer-events-auto flex flex-wrap justify-end gap-2 max-w-[80%]">
         
         {/* --- EXPANSION SLIDER --- */}
         <div className="bg-gray-900 border border-gray-600 rounded px-3 py-1 flex items-center gap-3 shadow-xl">
            <span className="text-[9px] font-bold text-gray-500 uppercase">Dense</span>
            <input 
                type="range" 
                min="0.5" 
                max="5.0" 
                step="0.1" 
                value={expansion} 
                onChange={(e) => setExpansion(parseFloat(e.target.value))}
                className="w-24 h-1 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
            />
            <span className="text-[9px] font-bold text-gray-500 uppercase">Expanded</span>
         </div>

         <div className="relative group">
            <select className="bg-gray-900 border border-gray-600 rounded pl-2 pr-8 py-1.5 text-xs text-white focus:border-green-500 focus:outline-none shadow-xl appearance-none cursor-pointer hover:bg-gray-800"
                value={selectedDc} onChange={(e) => setSelectedDc(e.target.value)}>
                <option value="all">All Datacenters</option>
                {availableSites.map((site) => <option key={site.slug} value={site.slug}>{site.name}</option>)}
            </select>
            <div className="absolute right-2 top-2 pointer-events-none text-gray-400">
                <ChevronRight size={12} className="rotate-90" />
            </div>
         </div>

         {/* --- SEARCH BAR RESTORED --- */}
         <div className="relative group">
            <Search className="absolute left-2 top-1.5 text-gray-500" size={14} />
            <input 
                type="text" 
                placeholder="Find Host..." 
                className="bg-gray-900 border border-gray-600 rounded pl-8 pr-8 py-1.5 text-xs text-white focus:border-green-500 focus:outline-none w-24 focus:w-48 shadow-xl transition-all"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
            />
            {searchTerm && <button onClick={() => setSearchTerm('')} className="absolute right-2 top-1.5 text-gray-500 hover:text-white"><X size={14}/></button>}
         </div>

         <div className="flex rounded border border-gray-600 bg-gray-900 overflow-hidden shadow-xl">
              <button onClick={() => setShowAllowed(!showAllowed)} className={`px-3 py-1.5 text-xs font-bold transition-all flex items-center gap-2 ${showAllowed ? 'bg-green-900/40 text-green-400' : 'bg-gray-800 text-gray-500'}`}><ShieldCheck size={12}/></button>
              <div className="w-px bg-gray-600"></div>
              <button onClick={() => setShowBlocked(!showBlocked)} className={`px-3 py-1.5 text-xs font-bold transition-all flex items-center gap-2 ${showBlocked ? 'bg-red-900/40 text-red-400' : 'bg-gray-800 text-gray-500'}`}><ShieldAlert size={12}/></button>
         </div>

         <button onClick={() => setShowExternal(!showExternal)} className={`px-2 py-1.5 rounded border text-xs font-bold shadow-xl transition-all flex items-center gap-2 ${showExternal ? 'bg-purple-900/40 text-purple-400 border-purple-500' : 'bg-gray-800 text-gray-500 border-gray-600'}`}>
            <Sparkles size={14} className={showExternal ? 'animate-pulse' : ''} />
            {showExternal ? 'DENSITY: HIGH' : 'DENSITY: LOW'}
         </button>

         <button onClick={() => setPerformanceMode(!performanceMode)} className={`px-2 py-1.5 rounded border text-xs font-bold shadow-xl transition-all flex items-center gap-2 ${performanceMode ? 'bg-green-900/40 text-green-400 border-green-500' : 'bg-gray-800 text-gray-500 border-gray-600'}`}>
            <Activity size={14} className={performanceMode ? 'animate-pulse' : ''} />
            {performanceMode ? 'PERF: ON' : 'PERF: OFF'}
         </button>

         <button onClick={handleRecenter} className="p-1.5 rounded border bg-gray-800 border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white shadow-xl"><RefreshCw size={14} /></button>
         
         <button onClick={() => setViewMode(prev => prev === '2D' ? '3D' : '2D')} className="px-2 py-1.5 rounded border text-xs font-bold shadow-xl bg-gray-800 text-blue-400 border-gray-600 hover:text-white">{viewMode}</button>
         {viewMode === '3D' && (
            <button onClick={() => setShowWireframe(!showWireframe)} className={`px-2 py-1.5 rounded border text-xs font-bold shadow-xl ${showWireframe ? 'bg-blue-900/40 text-blue-400 border-blue-500' : 'bg-gray-800 text-gray-500 border-gray-600'}`}><GlobeIcon size={14}/></button>
         )}
         <button onClick={() => setShowLabels(!showLabels)} className={`px-2 py-1.5 rounded border text-xs font-bold shadow-xl ${showLabels ? 'bg-gray-700 text-white border-gray-500' : 'bg-gray-800 text-gray-400 border-gray-600'}`}>{showLabels ? "ABC" : "..."}</button>
         <button onClick={togglePause} className={`p-1.5 rounded border shadow-xl ${isPaused ? 'bg-yellow-500/20 border-yellow-500 text-yellow-500' : 'bg-gray-800 border-gray-600 text-gray-300'}`}>{isPaused ? <Play size={14} /> : <Pause size={14} />}</button>
      </div>
      
      {/* TOOLTIP */}
      {tooltipNode && (
        <div 
            className="absolute z-50 bg-black/90 border border-gray-700 p-3 rounded text-xs text-white pointer-events-none shadow-xl backdrop-blur max-w-xs"
            style={{ left: hoverPos.x + 10, top: hoverPos.y + 10 }}
        >
            <div className="font-bold text-green-400 mb-1">{tooltipNode.name || tooltipNode.id}</div>
            <div className="text-[10px] text-gray-400 mb-2">Score: {tooltipNode.score?.toFixed(2)}</div>
            <div className="border-t border-gray-800 pt-1">
                <div className="text-[9px] uppercase text-gray-500 font-bold mb-1">Connections</div>
                {getNeighbors(tooltipNode).map(n => (
                    <div key={n} className="font-mono text-gray-300 truncate">{n}</div>
                ))}
                {getNeighbors(tooltipNode).length === 0 && <div className="text-gray-600 italic">No active links</div>}
            </div>
        </div>
      )}
      
      {/* GRAPH */}
      {viewMode === '3D' ? (
      <ForceGraph3D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        backgroundColor="#050505"
        
        // --- 3D NODE STYLING (Matched to 2D) ---
        nodeColor={node => {
            if (node.score > 5) return THEME.red;
            if (node.score > 2) return THEME.orange;
            if (node.type === 'src') return THEME.green;
            return THEME.blue;
        }}
        nodeRelSize={1.5}
        nodeVal={3}
        // Disable default label since we use sprites
        nodeLabel={null} 
        nodeOpacity={0.9}
        nodeResolution={16} 

        // --- LABELS (Sprites) ---
        nodeThreeObjectExtend={true}
        nodeThreeObject={node => {
            // 1. Check if node is part of the active view (filtered)
            const isActive = !activeIds || activeIds.has(node.id);
            if (!isActive) return null;

            // 2. Check if label should be visible (Importance check)
            // Always show if it's the selected node itself
            const isSelectedTarget = selectedNode && selectedNode.id === node.id;
            // Otherwise obey standard rules: Toggle ON or Score > 2
            if (!showLabels && node.score < 2 && !isSelectedTarget) return null;
            
            const sprite = new SpriteText(node.name || node.id);
            sprite.color = node.score > 5 ? '#ffaaaa' : '#e0e0e0';
            sprite.textHeight = 8; // Fixed height
            sprite.position.y = 8; // Offset above node
            return sprite;
        }}

        // --- WIREFRAME ---
        onSceneMounted={scene => {
            // Remove existing wireframe if any
            const existing = scene.children.find(c => c.name === 'galaxy-wireframe');
            if (existing) scene.remove(existing);

            if (showWireframe) {
                const geometry = new THREE.IcosahedronGeometry(300, 2); // 300 radius, 2 detail
                const material = new THREE.MeshBasicMaterial({ 
                    color: 0x3b82f6, 
                    wireframe: true, 
                    transparent: true, 
                    opacity: 0.1 
                });
                const mesh = new THREE.Mesh(geometry, material);
                mesh.name = 'galaxy-wireframe';
                
                // Add slow rotation script attached to the object userdata for later? 
                // Or just static. Static is fine for context.
                scene.add(mesh);
            }
        }}
        // Trigger scene update when wireframe toggles
        onRenderFramePre={scene => {
             // Rotate wireframe if it exists
             const wireframe = scene.children.find(c => c.name === 'galaxy-wireframe');
             if (wireframe) {
                 wireframe.rotation.y += 0.001;
                 wireframe.rotation.x += 0.0005;
             }
        }}

        // --- 3D LINK STYLING (Matched to 2D) ---
        linkColor={link => {
            const sScore = link.source.score || 0; 
            const tScore = link.target.score || 0;
            if (sScore > 5 || tScore > 5) return 'rgba(239, 68, 68, 0.8)'; 
            if (link.type === 'block') return 'rgba(200, 80, 80, 0.25)'; 
            return 'rgba(150, 150, 150, 0.4)'; 
        }}
        linkWidth={link => (link.source.score > 5 || link.target.score > 5) ? 2 : 1}
        linkOpacity={0.4}
        
        // --- PARTICLES (Matched to 2D) ---
        linkDirectionalParticles={link => performanceMode ? 0 : ((link.source.score > 2 || link.target.score > 2) ? 4 : 1)}
        linkDirectionalParticleSpeed={link => (link.source.score > 5 || link.target.score > 5) ? 0.006 : 0.002}
        linkDirectionalParticleWidth={3}
        linkDirectionalParticleColor={() => '#ffffff'}
        linkDirectionalParticleResolution={8}

        // --- CONTROLS ---
        controlType="orbit" // Allows spinning
        enableNodeDrag={true}
        enableNavigationControls={true}
        showNavInfo={true}
        onNodeClick={(node) => {
            setSelectedNode(node);
            if (onNodeClick) onNodeClick(node);
            if (fgRef.current) {
                // Aim at node
                const distance = 100;
                const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);
                fgRef.current.cameraPosition(
                    { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio }, // new position
                    node, // lookAt ({ x, y, z })
                    3000  // ms transition duration
                );
            }
        }}
        onBackgroundClick={handleBackgroundClick}
        
        // --- PHYSICS ---
        d3VelocityDecay={0.9} // High friction to stop bouncing (matched to 2D)
        d3AlphaDecay={0.05}   // Faster stabilization
        
        // --- INTERACTION ---
        onNodeHover={(node, prevNode) => {
            setTooltipNode(node);
            // We can't get mouse coords from this event easily in 3D canvas without raycaster logic.
            // But we can update state. 
            // Actually, react-force-graph exposes 'onNodeClick', etc. 
            // For hovering in 3D, we usually rely on the library's built-in tooltip `nodeLabel`.
            // But we wanted custom HTML.
            // We can capture mousemove on the CONTAINER.
        }}
      />
      ) : (
      <ForceGraph2D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        backgroundColor="#050505"
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={(node, color, ctx) => {
            ctx.fillStyle = color;
            ctx.beginPath(); ctx.arc(node.x, node.y, 4, 0, 2 * Math.PI, false); ctx.fill();
        }}
        linkCurvature={0.25}
        
        // --- PHYSICS (2D STABILIZATION) ---
        d3VelocityDecay={0.9} 
        d3AlphaDecay={0.05}
        
        // --- PARTICLES (2D) ---
        linkDirectionalParticles={link => {
            if (performanceMode) return 0;
            if (activeIds) {
               const srcId = typeof link.source === 'object' ? link.source.id : link.source;
               const dstId = typeof link.target === 'object' ? link.target.id : link.target;
               // O(1) check
               if (!activeIds.has(srcId) || !activeIds.has(dstId)) return 0;
            }
            return (link.source.score > 2 || link.target.score > 2) ? 4 : 1;
        }}
        linkDirectionalParticleSpeed={link => (link.source.score > 5 || link.target.score > 5) ? 0.006 : 0.002}
        linkDirectionalParticleWidth={3}
        linkDirectionalParticleColor={() => '#ffffff'}
        
        // --- INTERACTION (2D) ---
        onNodeHover={(node) => {
            setTooltipNode(node);
        }}
        onNodeClick={(node) => {
            setSelectedNode(node);
            if (onNodeClick) onNodeClick(node);
            if (fgRef.current) {
                fgRef.current.centerAt(node.x, node.y, 1000);
                fgRef.current.zoom(4, 2000);
            }
        }}
        onBackgroundClick={handleBackgroundClick}
        
        // --- LINK STYLING (2D) ---
        linkColor={link => {
            if (activeIds) {
               const srcId = typeof link.source === 'object' ? link.source.id : link.source;
               const dstId = typeof link.target === 'object' ? link.target.id : link.target;
               // O(1) check
               if (!activeIds.has(srcId) || !activeIds.has(dstId)) return 'rgba(0,0,0,0.02)'; 
            }
            
            const sScore = link.source.score || 0; 
            const tScore = link.target.score || 0;
            if (sScore > 5 || tScore > 5) return 'rgba(239, 68, 68, 0.8)'; 
            if (link.type === 'block') return 'rgba(200, 80, 80, 0.25)'; 
            return 'rgba(150, 150, 150, 0.4)'; 
        }}
      />
      )}
    </div>
  );
};

// --- COMPONENT: DESTINATIONS MAP ---
const DestinationsMap = ({ destinations, stats }) => {
  // DATACENTER GEOGRAPHIES
  const LOCATIONS = {
    nyc: { id: "nyc", name: "NYC", full_name: "New York, US", lat: 40.7128, lng: -74.0060, color: '#3b82f6' },
    dal: { id: "dal", name: "DAL", full_name: "Dallas, US", lat: 32.7767, lng: -96.7970, color: '#3b82f6' },
    lon: { id: "lon", name: "LON", full_name: "London, UK", lat: 51.5074, lng: -0.1278, color: '#3b82f6' },
    fra: { id: "fra", name: "FRA", full_name: "Frankfurt, DE", lat: 50.1109, lng: 8.6821, color: '#3b82f6' },
    prg: { id: "prg", name: "PRG", full_name: "Prague, CZ", lat: 50.0755, lng: 14.4378, color: '#3b82f6' },
    hkg: { id: "hkg", name: "HKG", full_name: "Hong Kong, HK", lat: 22.3193, lng: 114.1694, color: '#3b82f6' },
    sgp: { id: "sgp", name: "SGP", full_name: "Singapore, SG", lat: 1.3521, lng: 103.8198, color: '#3b82f6' }
  };

  // CIDR TO LOCATION MAPPINGS
  const CIDR_MAPPINGS = [
    { cidr: "10.250.0.0/20", loc: "nyc" },
    { cidr: "10.150.253.0/24", loc: "nyc" },
    { cidr: "10.250.16.0/20", loc: "dal" },
    { cidr: "10.150.20.0/24", loc: "dal" },
    { cidr: "10.250.32.0/20", loc: "lon" },
    { cidr: "10.160.65.0/24", loc: "lon" },
    { cidr: "10.250.64.0/20", loc: "fra" },
    { cidr: "10.250.80.0/20", loc: "prg" },
    { cidr: "10.150.0.0/24", loc: "hkg" },
    { cidr: "10.150.1.0/24", loc: "nyc" },
    { cidr: "10.150.2.0/24", loc: "nyc" },
    { cidr: "10.150.3.0/24", loc: "nyc" }
  ];

  const DATACENTERS = Object.values(LOCATIONS);

  // HELPER: IP TO LOCATION
  const ipToLong = (ipAddr) => {
    const parts = ipAddr.split('.');
    if (parts.length !== 4) return 0;
    return ((parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) | (parseInt(parts[2]) << 8) | parseInt(parts[3])) >>> 0;
  };

  const getSourceLocation = (ip) => {
    if (!ip) return { ...LOCATIONS.nyc, unknown: true };

    const ipLong = ipToLong(ip);

    for (const mapping of CIDR_MAPPINGS) {
        const [range, bits] = mapping.cidr.split('/');
        const mask = ~((1 << (32 - parseInt(bits))) - 1);
        if ((ipLong & mask) === (ipToLong(range) & mask)) {
            return { ...LOCATIONS[mapping.loc], unknown: false };
        }
    }
    // If it starts with 10. and wasn't found, it's an unlabeled internal subnet
    return { ...LOCATIONS.nyc, unknown: ip.startsWith('10.') };
  };
  
  const [globeData, setGlobeData] = useState({ arcs: [], points: [], labels: [] });
  const [unlabeledSubnets, setUnlabeledSubnets] = useState([]);
  const globeEl = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useLayoutEffect(() => {
    if (!containerRef.current) return;
    const resizeObserver = new ResizeObserver((entries) => {
        for (let entry of entries) {
            const { width, height } = entry.contentRect;
            if (width > 0 && height > 0) {
                setDimensions({ width, height });
            }
        }
    });
    resizeObserver.observe(containerRef.current);
    return () => resizeObserver.disconnect();
  }, []);

  useEffect(() => {
    if (globeEl.current) {
        // Stop Auto-rotate
        globeEl.current.controls().autoRotate = false;
        // Center the view (Atlantic View to show all DCs)
        globeEl.current.pointOfView({ lat: 35, lng: -40, altitude: 2.5 });
    }
  }, []);

  useEffect(() => {
    if (!destinations) return;
    
    const arcs = [];
    const points = [...DATACENTERS]; 
    const labels = [...DATACENTERS];
    const unknownMap = {};

    // OPTIMIZATION: Limit to 100 recent destinations to prevent GPU lag
    const recentDestinations = destinations.slice(0, 100);

    recentDestinations.forEach(d => {
       if (d.lat === null || d.lon === null || d.lat === undefined || d.lon === undefined) return;
       
       // Determine Source
       const sourceLoc = getSourceLocation(d.src_ip);
       
       // Track unknown 10/8 subnets
       if (sourceLoc.unknown && d.src_ip.startsWith('10.')) {
           const subnet = d.src_ip.split('.').slice(0, 3).join('.') + '.0/24';
           unknownMap[subnet] = (unknownMap[subnet] || 0) + 1;
       }

       const destPoint = { 
           lat: d.lat, 
           lng: d.lon, 
           name: d.city || d.country,
           color: THEME.orange,
           ...d // Pass full data for tooltip
       };

       points.push(destPoint);
       labels.push(destPoint);

       arcs.push({
           startLat: sourceLoc.lat,
           startLng: sourceLoc.lng,
           endLat: d.lat,
           endLng: d.lon,
           color: sourceLoc.unknown ? [THEME.red, THEME.orange] : [THEME.blue, THEME.green], 
           ...d
       });
    });

    setGlobeData({ arcs, points, labels });
    
    // Process unknown subnets into sorted array
    const sortedUnknown = Object.entries(unknownMap)
        .map(([subnet, count]) => ({ subnet, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
    setUnlabeledSubnets(sortedUnknown);

  }, [destinations]);

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* MAP COLUMN */}
      <div className="w-full h-[800px] bg-[#050505] rounded-lg overflow-hidden border border-gray-800 relative" ref={containerRef}>
       {/* HEADER */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <div className="bg-black/80 p-2 rounded border border-gray-700 backdrop-blur">
          <h3 className="text-sm font-bold text-gray-200 flex items-center gap-2">
            <GlobeIcon size={16} className="text-blue-500"/>
            Live Traffic Destinations (3D)
          </h3>
          <div className="text-[10px] text-gray-500">
             Origin: Global Datacenters (NYC, DAL, LON, FRA, PRG)
          </div>
        </div>
      </div>
      
      <Globe
        ref={globeEl}
        width={dimensions.width}
        height={dimensions.height}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
        backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
        backgroundColor="#050505"
        
        // --- ARCS (Traffic Flow) ---
        arcsData={globeData.arcs}
        arcColor={'color'}
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={2000} 
        arcStroke={0.5}
        arcAltitude={0.2} 
        
        // Tooltip for Arcs
        arcLabel={d => `
            <div class="bg-black/90 p-2 rounded border border-gray-700 text-xs font-mono">
                <div class="text-green-400 font-bold">Traffic Flow</div>
                <div>Src: ${d.src_ip || '?'}:${d.src_port || '?'}</div>
                <div>Dst: ${d.ip || '?'}:${d.dst_port || '?'}</div>
            </div>
        `}

        // --- POINTS (Cities) ---
        pointsData={globeData.points}
        pointColor={'color'}
        pointAltitude={0.01}
        pointRadius={0.2}
        pointResolution={8} 
        pointsMerge={true} 
        // Tooltip for Points
        pointLabel={d => `
            <div class="bg-black/90 p-2 rounded border border-gray-700 text-xs font-mono">
                <div class="font-bold ${d.id ? 'text-blue-500' : 'text-orange-500'}">${d.name}</div>
                ${d.asn ? `<div class="text-gray-400 text-[10px]">AS${d.asn} (${d.org})</div>` : ''}
                ${d.full_name ? `<div class="text-gray-400 text-[10px]">${d.full_name}</div>` : ''}
            </div>
        `}

        // --- LABELS (Text) ---
        labelsData={globeData.labels}
        labelLat={d => d.lat}
        labelLng={d => d.lng}
        labelText={d => d.name}
        labelSize={d => d.id ? 1.5 : 0.5} 
        labelDotRadius={0.3}
        labelColor={() => 'rgba(255, 255, 255, 0.75)'}
        labelResolution={1} 
      />
      
      </div>

      {/* STATS SECTION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* LEFT: Top Destination Countries */}
          <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 flex flex-col h-[300px]">
              <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                 <GlobeIcon size={16}/> Top Destination Countries
              </h3>
              <div className="flex-1">
                 {stats && stats.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={stats} margin={{top: 0, right: 30, left: 40, bottom: 0}}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
                            <XAxis type="number" hide />
                            <YAxis dataKey="name" type="category" width={80} tick={{fontSize: 10, fill: '#888'}} interval={0} />
                            <Tooltip 
                                cursor={{fill: '#ffffff10'}} 
                                contentStyle={{backgroundColor: '#000', borderColor: '#333', color: '#fff'}}
                                itemStyle={{color: '#fff'}}
                            />
                            <Bar dataKey="count" fill={THEME.blue} radius={[0, 4, 4, 0]} barSize={20}>
                                {stats.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={index === 0 ? THEME.green : THEME.blue} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                 ) : (
                    <div className="h-full flex items-center justify-center text-gray-600 text-xs">
                        Collecting stats...
                    </div>
                 )}
              </div>
          </div>

          {/* RIGHT: Unlabeled Internal Subnets */}
          <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 flex flex-col h-[300px]">
              <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                 <Filter size={16} className="text-orange-500"/> Unlabeled Internal Subnets (10.0.0.0/8)
              </h3>
              <div className="flex-1 overflow-y-auto custom-scrollbar">
                  {unlabeledSubnets.length > 0 ? (
                      <table className="w-full text-left text-xs">
                          <thead className="text-gray-500 border-b border-gray-800 sticky top-0 bg-[#121212]">
                              <tr>
                                  <th className="pb-2">Subnet (/24)</th>
                                  <th className="pb-2 text-right">Hit Count</th>
                              </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-800">
                              {unlabeledSubnets.map((item, i) => (
                                  <tr key={i} className="hover:bg-gray-800/50">
                                      <td className="py-2 font-mono text-orange-400">{item.subnet}</td>
                                      <td className="py-2 text-right text-gray-400 font-bold">{item.count}</td>
                                  </tr>
                              ))}
                          </tbody>
                      </table>
                  ) : (
                      <div className="h-full flex items-center justify-center text-gray-600 text-xs italic">
                          No unlabeled 10/8 traffic detected in current buffer.
                      </div>
                  )}
              </div>
          </div>
      </div>
    </div>
  );
};

function App() {
  const [data, setData] = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);
  const [showExternal, setShowExternal] = useState(false); 
  const [performanceMode, setPerformanceMode] = useState(false); 

  // Chat & Proactive Alert State
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Hello! I am Defense Halo AI. How can I help you analyze your network security today?' }
  ]);
  const alertedHostsRef = useRef(new Set());

  const handleHostClick = (host) => {
    // If we only have the ID (e.g. from Galaxy or Logs), find the full object from topology
    if (typeof host === 'string') {
        const fullHost = data?.topology?.nodes?.find(n => n.id === host || n.name === host);
        if (fullHost) {
            setSelectedHost(fullHost);
        } else {
            // Fallback for unknown hosts
            setSelectedHost({ id: host, name: host, score: 0 });
        }
    } else {
        setSelectedHost(host);
    }
  };

  const triggerProactiveAlert = async (hostId, score, reason) => {
    if (alertedHostsRef.current.has(hostId)) return;
    alertedHostsRef.current.add(hostId);

    // 1. Add System Notification (Note: auto-show setIsChatOpen(true) removed per user request)
    const systemMsg = { role: 'system', content: `CRITICAL ANOMALY DETECTED: ${hostId}` };
    setChatMessages(prev => [...prev, systemMsg]);

    // 2. Request AI Analysis
    const prompt = `A critical anomaly of ${score.toFixed(2)} was just detected on host ${hostId} for the reason: "${reason || 'Unknown'}". Please analyze this and provide immediate recommendations.`;
    
    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                message: prompt, 
                context: {
                    target_host: hostId,
                    anomaly_score: score,
                    anomaly_reason: reason,
                    metrics: data?.metrics,
                    threat_level: data?.threat_score?.score
                }
            })
        });

        if (response.ok) {
            const result = await response.json();
            setChatMessages(prev => [...prev, { role: 'assistant', content: result.response }]);
        }
    } catch (e) {
        console.error("Proactive Alert Failed:", e);
    }
  };

    const [logHistory, setLogHistory] = useState([]);
    const [firewallHistory, setFirewallHistory] = useState([]);
    const [aggregatedStats, setAggregatedStats] = useState({ countries: {}, hosts: {}, attackCountries: {} });  const [status, setStatus] = useState("Initializing Link...");
  const [activeTab, setActiveTab] = useState("overview"); 
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedSystem, setSelectedSystem] = useState(null);
  const [focusHost, setFocusHost] = useState('');
  const [majorAnomalyEventsWithLogs, setMajorAnomalyEventsWithLogs] = useState([]);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [weights, setWeights] = useState({
    critical: { enabled: true, value: 20, label: "Critical Alerts" },
    authFail: { enabled: true, value: 10, label: "Auth Failures" },
    root: { enabled: true, value: 5, label: "Root Activity" },
    block: { enabled: true, value: 5, label: "Firewall Blocks" },
    sudo: { enabled: true, value: 2, label: "Sudo Commands" }
  });
  
  const [feeds, setFeeds] = useState(DEFAULT_FEEDS);
  const [scatterMode, setScatterMode] = useState('bytes');
  const [netflowBuffer, setNetflowBuffer] = useState([]);
  const [netflowLogBuffer, setNetflowLogBuffer] = useState([]);
  const [trafficTrend, setTrafficTrend] = useState([]);

  const addFeed = (newFeed) => {
    if (!feeds.find(feed => feed.url === newFeed.url)) {
      setFeeds([...feeds, newFeed]);
    }
  };

  const removeFeed = (url) => {
    setFeeds(feeds.filter(feed => feed.url !== url));
  };

  const seenLogSignatures = useRef(new Set());
  const seenFirewallSignatures = useRef(new Set());
  const selectedUserRef = useRef(null);
  const logHistoryRef = useRef([]);
  const firewallHistoryRef = useRef([]);
  const wsRef = useRef(null);

  useEffect(() => {
    selectedUserRef.current = selectedUser;
  }, [selectedUser]);

  useEffect(() => {
    document.title = "GTT Halo  Real-Time Threat Intelligence";
  }, []);

  useEffect(() => {
    // Sync density and performance toggle to backend whenever they change
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ 
            type: 'filter_update', 
            show_external: showExternal,
            performance_mode: performanceMode 
        }));
    }
  }, [showExternal, performanceMode]);

  useEffect(() => {
    // Determine WebSocket URL - Handle K8s/Rancher deployments
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Fallback logic: If we're on a standard port (80/443), the backend might be on the same port via Ingress
    const backendPort = (window.location.port === '' || window.location.port === '80' || window.location.port === '443') 
        ? '5174' // Default to 15174, but users can override this if they use an Ingress
        : '5174'; 
    
    //const wsUrl = `${protocol}//${window.location.hostname}:${backendPort}/ws`
    let wsUrl = window._env_?.VITE_WS_URL || import.meta.env.VITE_WS_URL || '/ws';
    // If the URL is relative, construct an absolute URL using current page's host and protocol
    if (wsUrl.startsWith('/')) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host; // includes port if present
        wsUrl = `${protocol}//${host}${wsUrl}`;
    }
    
    console.log("Configuration Sources:", {
      runtime: window._env_?.VITE_WS_URL,
      buildTime: import.meta.env.VITE_WS_URL,
      final: wsUrl,
      density: showExternal ? 'HIGH' : 'LOW',
      performance: performanceMode ? 'ON' : 'OFF'
    });
    console.log(`🔌 Connecting to WebSocket: ${wsUrl}`);
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
        setStatus("Connected");
        // Sync current state immediately
        ws.send(JSON.stringify({ 
            type: 'filter_update', 
            show_external: showExternal,
            performance_mode: performanceMode
        }));
    };
    
    // Helper: Convert HH:MM:SS to seconds
    const toSeconds = (t) => {
        if (!t) return 0;
        const [h, m, s] = t.split(':').map(Number);
        return h * 3600 + m * 60 + s;
    };

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);

        if (!parsed || !parsed.tables) {
            console.warn("Skipping malformed data packet:", parsed);
            return; 
        }

        let normalizedLogs = [];

        if (parsed.tables?.logs) {
             normalizedLogs = parsed.tables.logs.map(normalizeLog);
        }
        
        let currentHistory = logHistoryRef.current; 
        let uniqueIncomingLogs = [];

        if (normalizedLogs.length > 0) {
          uniqueIncomingLogs = normalizedLogs.reduce((acc, log) => {
              const cleanName = sanitizeUser(log.user);
              const cleanLog = { ...log, user: cleanName || 'unknown' };
              const sig = getLogSignature(cleanLog);

              if (!seenLogSignatures.current.has(sig)) {
                  seenLogSignatures.current.add(sig);
                  acc.push(cleanLog);
              }
              return acc;
          }, []);
        }

        const updatedHistory = [...uniqueIncomingLogs, ...currentHistory];

        if (seenLogSignatures.current.size > 15000) {
             seenLogSignatures.current.clear();
             updatedHistory.slice(0, 5000).forEach(l => {
                 seenLogSignatures.current.add(getLogSignature(l));
             });
        }

        const finalHistory = updatedHistory.slice(0, 5000);
        logHistoryRef.current = finalHistory;

        if (uniqueIncomingLogs.length > 0) {
           setLogHistory(finalHistory);
        }

        // --- NEW: FIREWALL LOG PROCESSING ---
        let uniqueFirewallLogs = [];
        if (parsed.tables?.firewall_logs) {
            const normalizedFirewall = parsed.tables.firewall_logs.map(normalizeLog);
            uniqueFirewallLogs = normalizedFirewall.reduce((acc, log) => {
                const sig = getLogSignature(log);
                if (!seenFirewallSignatures.current.has(sig)) {
                    seenFirewallSignatures.current.add(sig);
                    acc.push(log);
                }
                return acc;
            }, []);
        }

        if (uniqueFirewallLogs.length > 0) {
            const updatedFirewall = [...uniqueFirewallLogs, ...firewallHistoryRef.current].slice(0, 1000);
            firewallHistoryRef.current = updatedFirewall;
            setFirewallHistory(updatedFirewall);
            
            // Clean up signatures periodically
            if (seenFirewallSignatures.current.size > 15000) {
                seenFirewallSignatures.current.clear();
                updatedFirewall.slice(0, 500).forEach(l => seenFirewallSignatures.current.add(getLogSignature(l)));
            }
        }

        if (parsed.tables?.major_anomaly_events) {
          const newEvents = parsed.tables.major_anomaly_events.filter(event => 
            !majorAnomalyEventsWithLogs.some(existing => existing.host === event.host && existing.time === event.time)
          );

          if (newEvents.length > 0) {
            const newEventsWithLogs = newEvents.map(event => {
              const eventTimeSeconds = toSeconds(event.time);
              const associatedLogs = finalHistory.filter(log => {
                  const isHostMatch = log.host === event.host || (log.source && log.source === event.host);
                  if (!isHostMatch) return false;
                  const logTimeSeconds = toSeconds(log.time);
                  let diff = eventTimeSeconds - logTimeSeconds;
                  if (diff < -40000) diff += 86400; 
                  const inTimeWindow = diff >= -10 && diff <= 300;
                  if (!inTimeWindow) return false;
                  const isHighAiScore = log.anomaly_score > 0.5;
                  const isHighPriority = log.priority === 'critical' || log.priority === 'high';
                  const isSecurityIncident = log.category === 'auth_fail' || log.category === 'security';
                  return isHighAiScore || isHighPriority || isSecurityIncident;
              }).slice(0, 50); 

              return { ...event, logs: associatedLogs };
            });
            setMajorAnomalyEventsWithLogs(prev => [...newEventsWithLogs, ...prev].slice(0, 50));
          }
        }

        // --- ENHANCED NETFLOW BUFFER LOGIC (Relaxed for Table) ---
        let currentNetflowLogs = [];
        if (parsed.netflow && parsed.netflow.scatter && parsed.netflow.scatter.length > 0) {
           
           // 1. DATA REPAIR
           const fixedPoints = parsed.netflow.scatter.map(p => {
               const cause = p.cause || '';
               const portMatch = cause.match(/Dest Port \((\d+)\)/i);
               if (portMatch) {
                   return { ...p, port: parseInt(portMatch[1], 10) };
               }
               return p;
           });

           // 2. BASIC FILTERING (Subnet + Noise Only)
           const validPoints = fixedPoints.filter(point => {
               // A. IP Subnet Filter - Disabled to show all DFP results
               // if (!isInTargetSubnet(point.host)) return false;

               // B. Noise Filter - Disabled to see the full DFP learning output
               // const cause = (point.cause || '').toLowerCase();
               // if (cause.includes('byte') || 
               //    cause.includes('volume') || 
               //    cause.includes('packet count')) return false;

               // REMOVED: The score check (point.y <= 2.0) is gone. 
               // Now ALL scores enter the system.

               return true;
           });

           if (validPoints.length > 0) {
               // 3. UPDATE BUFFERS
               setNetflowBuffer(prev => {
                  const combined = [...validPoints, ...prev];
                  return combined.slice(0, 1000); 
               });

               currentNetflowLogs = validPoints.map(p => ({
                   time: new Date().toLocaleTimeString('en-US', { hour12: false }),
                   host: p.host,
                   category: 'Netflow DFP',
                   priority: p.y > 5 ? 'critical' : p.y > 2 ? 'high' : 'low', // Dynamic priority
                   is_sec: true,
                   anomaly_score: p.y,
                   msg: `AutoEncoder Divergence: ${p.cause} (Vol: ${p.bytes}, Port: ${p.port})`,
                   uuid: `${p.host}-${Date.now()}-${Math.random()}`
               }));

               setNetflowLogBuffer(prev => {
                   const combinedLogs = [...currentNetflowLogs, ...prev];
                   return combinedLogs.slice(0, 1000); 
               });
           }
        }
        
        // --- TRAFFIC TREND AGGREGATION ---
        let allowCount = 0;
        let blockCount = 0;

        // Count Syslog (Only Firewall Related)
        uniqueIncomingLogs.forEach(l => {
             const isFirewall = l.category === 'firewall_block' || l.category === 'Firewall' || (l.msg || '').toLowerCase().includes('%ftd');
             if (!isFirewall) return;

             const text = (l.msg || '').toLowerCase();
             const isBlock = text.includes('block') || text.includes('deny') || text.includes('drop') || l.priority === 'critical';
             if(isBlock) blockCount++; else allowCount++;
        });

        // Count Netflow
        currentNetflowLogs.forEach(l => {
             const isBlock = l.priority === 'critical' || l.priority === 'high';
             if(isBlock) blockCount++; else allowCount++;
        });

        if (allowCount > 0 || blockCount > 0) {
            setTrafficTrend(prev => {
                const now = new Date().toLocaleTimeString('en-US', { hour12: false });
                const newItem = { time: now, Allow: allowCount, Block: blockCount };
                return [...prev, newItem].slice(-60); // Keep last 60 points
            });
        }
        
        // --- DESTINATIONS ---
        if (parsed.destinations) {
             // We can store this in the main data object, no special state needed if we pass data.destinations
        }

        setData(parsed);

        // --- PROACTIVE AI ALERTS ---
        if (parsed.anomalies?.top_hosts) {
            // Find the most critical anomaly in this update
            const criticalHost = parsed.anomalies.top_hosts.find(h => (h.score || h.current_score) > 8.0);
            if (criticalHost) {
                triggerProactiveAlert(criticalHost.host, criticalHost.score || criticalHost.current_score, criticalHost.reason);
            }
        }

        setAggregatedStats(prev => {
          const newCountries = { ...prev.countries };
          const newAttackCountries = { ...prev.attackCountries };
          const newHosts = { ...prev.hosts };
          
          if (parsed.charts?.top_countries) {
            parsed.charts.top_countries.forEach(item => {
              newCountries[item.name] = (newCountries[item.name] || 0) + item.count;
            });
          }
          if (parsed.charts?.top_attack_countries) {
            parsed.charts.top_attack_countries.forEach(item => {
              newAttackCountries[item.name] = (newAttackCountries[item.name] || 0) + item.count;
            });
          }
          if (parsed.charts?.top_hosts) {
            parsed.charts.top_hosts.forEach(item => {
              const existing = newHosts[item.host] || { total: 0, security: 0 };
              newHosts[item.host] = {
                  total: existing.total + (item.total || 0),
                  security: existing.security + (item.security || 0)
              };
            });
          }
          return { countries: newCountries, hosts: newHosts, attackCountries: newAttackCountries };
        });

        if (selectedUserRef.current) {
          const updatedUser = parsed.tables.users.find(u => u.user === selectedUserRef.current.user);
          if (updatedUser) {
               setSelectedUser(prev => {
                  if (!prev || prev.user !== updatedUser.user) return prev;
                  const mergedHosts = [...(prev.hosts || []), ...(updatedUser.hosts || [])];
                  const uniqueHosts = [...new Set(mergedHosts)];
                  return { ...updatedUser, hosts: uniqueHosts };
               }); 
          }
        }
      } catch (e) {
        // THIS is likely what is happening right now
        console.error("JSON PARSE ERROR:", e);
        console.log("Bad Data Snippet:", event.data.slice(-100)); // Show the end of the string
      }
    };

    ws.onclose = () => setStatus("Disconnected - Reconnecting...");
    return () => ws.close();
  }, [showExternal]);

  const systemLogHistory = useMemo(() => {
    return logHistory.filter(l => l.category !== 'Netflow DFP' && l.category !== 'firewall_block' && l.category !== 'Firewall');
  }, [logHistory]);

  const threatScore = useMemo(() => {
    if (!data?.tables?.logs || data.tables.logs.length === 0) return "0.0";
    let score = 0;
    const logs = logHistory.length > 0 ? logHistory.slice(0, 100) : data.tables.logs;
    logs.forEach(log => {
      if (weights.critical.enabled && (log.priority === 'critical' || log.priority === 'high')) score += weights.critical.value;
      if (weights.authFail.enabled && (log.category === 'auth_fail' || log.category === 'authentication')) score += weights.authFail.value;
      if (weights.block.enabled && log.is_sec) score += weights.block.value;
      if (weights.root.enabled && (log.category === 'sudo' || (log.msg || '').toLowerCase().includes('root'))) score += weights.root.value;
      if (log.anomaly_score > 0.8) score += 50; 
    });
    const normalized = score / 10; 
    return Math.min(normalized, 10.0).toFixed(1);
  }, [logHistory, data, weights]);

  const mapMarkers = useMemo(() => {
    if (!data || !data.map) return [];
    const validPoints = data.map.filter(p => p && typeof p.lat === 'number' && typeof p.lon === 'number');
    const recentPoints = validPoints.slice(0, 500); 
    const grouped = {};
    recentPoints.forEach(p => {
      const key = `${p.lat.toFixed(2)},${p.lon.toFixed(2)}`;
      const isBlocked = p.action === 'block' || p.action === 'deny' || p.priority === 'critical';

      if (grouped[key]) {
        grouped[key].count += 1;
        if (isBlocked) grouped[key].isBlocked = true;
      } else {
        grouped[key] = { ...p, count: 1, isBlocked };
      }
    });
    // SORT: Blocked markers last to render on top
    return Object.values(grouped).sort((a, b) => (a.isBlocked === b.isBlocked) ? 0 : a.isBlocked ? 1 : -1);
  }, [data?.map]);

  const persistentCharts = useMemo(() => {
    const topCountries = Object.entries(aggregatedStats.countries)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count).slice(0, 5); 
      
    const topAttackCountries = Object.entries(aggregatedStats.attackCountries)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count).slice(0, 5);

    const allHosts = Object.entries(aggregatedStats.hosts)
      .map(([host, stats]) => ({ host, total: stats.total, security: stats.security, category: stats.category }));

    const topHosts = allHosts
      .filter(h => h.category !== 'Firewall')
      .sort((a, b) => b.total - a.total).slice(0, 10);

    const topFirewallHosts = allHosts
      .filter(h => h.category === 'Firewall')
      .sort((a, b) => b.total - a.total).slice(0, 10);

    return { topCountries, topHosts, topAttackCountries, topFirewallHosts };
  }, [aggregatedStats]);

  const firewallStats = useMemo(() => {
    // 1. Timeline comes from persistent state (smooth scrolling)
    // 2. Top Ports comes from raw log history (accurate aggregation)
    
    if (!logHistory.length) return { timeline: trafficTrend, topPorts: [] };

    // Calculate Top Ports
    const portMap = {};
    logHistory.slice(0, 2000).forEach(l => {
       const text = (l.msg || l.message || '').toLowerCase();
       // Basic filter for relevant logs
       if (!text.includes('block') && !text.includes('allow') && !text.includes('deny') && !text.includes('drop') && l.category !== 'Netflow DFP') return;
       
       const rawText = l.msg || l.message || '';
       const portMatch = rawText.match(/DstPort\s*:\s*(\d+)/i);
       const port = l.dst_port || (portMatch ? portMatch[1] : 'Unknown');
       
       // Determine action
       let isAllow = rawText.match(/allow/i) || (l.action && l.action.toLowerCase() === 'allow');
       if (l.category === 'Netflow DFP') isAllow = l.priority !== 'critical' && l.priority !== 'high';
       const action = isAllow ? 'Allow' : 'Block';

       if (port === 'Unknown') return;
       if (!portMap[port]) portMap[port] = { port: port, Allow: 0, Block: 0, total: 0 };
       portMap[port][action]++;
       portMap[port].total++;
    });
    
    const topPorts = Object.values(portMap).sort((a,b) => b.total - a.total).slice(0, 5);

    return { timeline: trafficTrend, topPorts }; 
  }, [trafficTrend, logHistory]);

  const userStats = useMemo(() => {
    if (!selectedUser || !logHistory.length) return { activity: [], categories: [] };
    const userLogs = logHistory.filter(l => {
        if (l.category === 'firewall_block' || l.category === 'Firewall') return false;
        if (l.user === selectedUser.user) return true;
        return (l.msg || '').includes(selectedUser.user);
    });
    const timeMap = {};
    userLogs.slice(0, 200).forEach(l => {
        if(!timeMap[l.time]) timeMap[l.time] = { time: l.time, count: 0 };
        timeMap[l.time].count++;
    });
    const activity = Object.values(timeMap).reverse();
    const catMap = {};
    userLogs.forEach(l => {
        const cat = l.category || 'Unknown';
        if(!catMap[cat]) catMap[cat] = 0;
        catMap[cat]++;
    });
    const categories = Object.entries(catMap).map(([name, value]) => ({ name, value }));
    return { activity, categories };
  }, [selectedUser, logHistory]);

  const burstStats = useMemo(() => {
    if (!logHistory.length) return [];
    const toSeconds = (t) => {
      if (!t) return 0;
      const [h, m, s] = t.split(':').map(Number);
      return h * 3600 + m * 60 + s;
    };
    const latestLog = logHistory[0];
    if (!latestLog || !latestLog.time) return [];
    
    const anchorTime = toSeconds(latestLog.time);
    const burstWindow = 60; 
    const counts = {};

    for (let i = 0; i < Math.min(logHistory.length, 2000); i++) {
        const l = logHistory[i];
        if (!l.user || l.user === 'unknown' || INVALID_USERS.has(l.user.toLowerCase())) continue;
        const logTime = toSeconds(l.time);
        let diff = anchorTime - logTime;
        if (diff < -40000) diff += 86400;
        if (diff > burstWindow) break;
        counts[l.user] = (counts[l.user] || 0) + 1;
    }
    return Object.entries(counts).map(([user, value]) => ({ user, value })).sort((a, b) => b.value - a.value).slice(0, 7); 
  }, [logHistory]);

  const usersOnSystem = useMemo(() => {
    // FIX: Use ?. on data.tables in the return statement as well
    if (!selectedSystem || !data?.tables?.users) return [];
    return data.tables.users.filter(u => u.hosts && u.hosts.includes(selectedSystem));
  }, [selectedSystem, data]);

  const consolidatedEvents = useMemo(() => {
    const topHosts = data?.anomalies?.top_hosts || [];
    const existingEvents = majorAnomalyEventsWithLogs || [];
    const eventMap = new Map(existingEvents.map(e => [e.host, e]));

    return topHosts.map(hostObj => {
      // 1. If the Right Panel already has this host, use that rich data
      if (eventMap.has(hostObj.host)) {
        return eventMap.get(hostObj.host);
      }

      // 2. Determine Current Score
      const currentScore = hostObj.score ?? hostObj.current_score ?? hostObj.anomaly_score ?? 0;

      // 3. Determine Previous Score (Smart Lookup)
      let previousScore = hostObj.previous_score ?? hostObj.last_score ?? null;

      // If not provided by backend, look for it in the recent logs
      if (previousScore === null && logHistory.length > 0) {
        // Find the most recent log for this host that has a DIFFERENT score
        const historicEntry = logHistory.find(l => 
             (l.host === hostObj.host || l.source === hostObj.host) && 
             typeof l.anomaly_score === 'number' &&
             l.anomaly_score > 0 &&
             // Ensure the score is different enough to be considered a "previous state"
             Math.abs(l.anomaly_score - currentScore) > 0.1 
        );
        if (historicEntry) {
            previousScore = historicEntry.anomaly_score;
        }
      }

      // 4. Return Synthetic Event
      return {
        host: hostObj.host,
        time: "Active Now", 
        current_score: currentScore,
        previous_score: previousScore, // Now populated!
        reason: "Critical Score Aggregate", 
        logs: logHistory.filter(l => 
             (l.host === hostObj.host || l.source === hostObj.host) && 
             (l.anomaly_score > 0 || l.priority === 'critical' || l.priority === 'high')
        ).slice(0, 50) 
      };
    });
  }, [data, majorAnomalyEventsWithLogs, logHistory]);

  if (!data) return <LoadingScreen status={status} />;

  return (
    <div className="flex h-screen bg-black text-gray-300 font-sans overflow-hidden">
      
      {/* SIDEBAR */}
      <aside className={`
        ${isSidebarOpen ? 'w-64' : 'w-0'} 
        bg-[#050505] border-r border-gray-900 flex flex-col transition-all duration-300 ease-in-out relative z-30
      `}>
        {/* Toggle Button */}
        <button 
          onClick={() => setIsSidebarOpen(!isSidebarOpen)}
          className={`
            absolute -right-4 top-1/2 -translate-y-1/2 z-40
            bg-[#121212] border border-gray-800 p-1 rounded-full text-gray-500 hover:text-white hover:border-gray-600 transition-all shadow-lg
          `}
        >
          {isSidebarOpen ? <ChevronLeft size={16}/> : <ChevronRight size={16}/>}
        </button>

        <div className={`flex-1 flex flex-col overflow-hidden ${isSidebarOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'} transition-opacity duration-200`}>
          <div className="p-6 border-b border-gray-900">
            <div className="flex flex-col gap-0.5">
              <h1 className="text-xl font-extrabold text-white tracking-tighter leading-none flex items-center gap-2">
                <img src="/gtt-logo.svg" alt="GTT" className="h-6 w-auto" />
                <span>DEFENSE HALO</span>
              </h1>
              <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                Real-Time Threat Intelligence
              </div>
            </div>
            <div className="flex items-center gap-2 mt-4 text-xs text-gray-500">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
              LIVE STREAM
            </div>
          </div>
          <nav className="flex-1 p-4 space-y-2 overflow-y-auto custom-scrollbar">
            <NavButton id="overview" label="Global Overview" icon={GlobeIcon} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="host_inventory" label="Host Inventory" icon={Server} activeTab={activeTab} setTab={setActiveTab} />
            
            <CollapsibleNavSection 
              label="Visualizations" 
              icon={Aperture} 
              activeTab={activeTab} 
              childIds={['galaxy', 'destinations', 'city', 'hive', 'torus']}
            >
              <NavButton id="galaxy" label="System Log Galaxy" icon={Orbit} activeTab={activeTab} setTab={setActiveTab} />
              <NavButton id="destinations" label="Destinations" icon={GlobeIcon} activeTab={activeTab} setTab={setActiveTab} />
              <NavButton id="city" label="Cyber City" icon={Building2} activeTab={activeTab} setTab={setActiveTab} />
              <NavButton id="hive" label="Behavioral Hive" icon={Box} activeTab={activeTab} setTab={setActiveTab} />
              <NavButton id="torus" label="Traffic Torus" icon={Disc} activeTab={activeTab} setTab={setActiveTab} />
            </CollapsibleNavSection>

            <NavButton id="anomalies" label="System Log DNA" icon={AlertTriangle} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="dfp" label="Network Netflow DNA" icon={Fingerprint} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="user" label="User Activity" icon={Users} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="host" label="Host Forensics" icon={Server} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="network" label="Network & Firewall" icon={MapIcon} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="netbox" label="Netbox CVEs" icon={Shield} activeTab={activeTab} setTab={setActiveTab} />
            <NavButton id="raw" label="Raw Data" icon={Terminal} activeTab={activeTab} setTab={setActiveTab} />
          </nav>
          <div className="p-4 border-t border-gray-900">
            <div className="text-xs text-gray-600 uppercase font-bold mb-2">System Status</div>
            <div className="flex justify-between text-xs text-gray-400 mb-1">
              <span>Kafka Link</span>
              <span className="text-green-500">Active</span>
            </div>
            <div className="flex justify-between text-xs text-gray-400">
              <span>Latency</span>
              <span className="text-green-500">12ms</span>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        
        {/* HEADER */}
        <header className="bg-black/50 backdrop-blur-md border-b border-gray-900 p-6 flex justify-between items-end z-10">
          <div>
            <h2 className="text-2xl font-bold text-white uppercase tracking-wide">
              {activeTab.replace('_', ' ')} Dashboard
            </h2>
            <p className="text-sm text-gray-500">Real-time security event processing and correlation</p>
          </div>
          <div className="flex items-center gap-6 relative">
              <DigitalClock />
              <div className="h-8 w-px bg-gray-800 hidden md:block"></div>
              <div className="text-right group">
                <div className="text-[10px] text-gray-500 uppercase font-bold tracking-widest">Threat Level (5m Avg)</div>
                <div className="flex items-center justify-end gap-2">
                  <span className={`text-3xl font-black ${
                      (data?.threat_score?.score || 0) > 8 ? 'text-red-500' : 
                      (data?.threat_score?.score || 0) > 4 ? 'text-orange-500' : 'text-green-500'
                  }`}>
                    {data?.threat_score?.score?.toFixed(1) || "0.0"}
                  </span>
                  <Shield size={24} className={
                      (data?.threat_score?.score || 0) > 8 ? 'text-red-500' : 'text-gray-700'
                  } />
                </div>
                <div className="text-[10px] text-gray-600 mt-1 flex items-center justify-end gap-1">
                   Next Update: <CountdownTimer targetTimestamp={data?.threat_score?.next_update} />
                </div>
              </div>
              <button onClick={() => setShowSettings(!showSettings)} className="p-2 text-gray-600 hover:text-white transition-colors">
                <Settings size={20} />
              </button>
          </div>
        </header>

        {/* SETTINGS DRAWER */}
        {showSettings && (
          <div className="absolute top-24 right-6 z-50 bg-[#121212] border border-gray-800 p-4 rounded-lg shadow-2xl w-96">
            <h4 className="text-xs font-bold text-gray-400 uppercase mb-3">Score Configuration</h4>
            <div className="space-y-2">
              {Object.entries(weights).map(([key, setting]) => (
                <label key={key} className="flex items-center justify-between text-sm cursor-pointer hover:text-green-400">
                  <span className="text-gray-300">{setting.label}</span>
                  <input type="checkbox" checked={setting.enabled} onChange={(e) => setWeights({...weights, [key]: {...setting, enabled: e.target.checked}})} className="accent-green-500"/>
                </label>
              ))}
            </div>
            <h4 className="text-xs font-bold text-gray-400 uppercase mt-6 mb-3">RSS Feeds</h4>
            <div className="space-y-2">
              <form onSubmit={(e) => {
                e.preventDefault();
                const name = e.target.elements.name.value;
                const url = e.target.elements.url.value;
                if (name && url) {
                  addFeed({ name, url });
                  e.target.reset();
                }
              }} className="flex items-center gap-2">
                <input type="text" name="name" placeholder="Feed Name" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-1/3 focus:border-green-500 focus:outline-none" />
                <input type="text" name="url" placeholder="Feed URL" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-2/3 focus:border-green-500 focus:outline-none" />
                <button type="submit" className="bg-green-500 text-white rounded px-2 py-1 text-xs font-bold">Add</button>
              </form>
              {feeds.map(feed => (
                <div key={feed.url} className="flex items-center justify-between text-sm">
                  <span className="text-gray-300">{feed.name}</span>
                  <button onClick={() => removeFeed(feed.url)} className="text-gray-500 hover:text-red-500">
                    <X size={12} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SCROLLABLE DASHBOARD CONTENT */}
        <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
          
          {/* --- TAB: GLOBAL OVERVIEW --- */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                <MetricCard label="Throughput" value={`${data.metrics.eps} EPS`} icon={Activity} color={THEME.green} />
                <MetricCard label="Notable Events" value={data.metrics.counts.security} icon={AlertTriangle} color={THEME.orange} />
                <MetricCard label="Auth Failures" value={data.metrics.counts.auth_fail} icon={Lock} color={THEME.red} />
                <MetricCard label="Active Users" value={data.metrics.seen_users} icon={Users} color="#3b82f6" />
                <MetricCard label="Active Hosts" value={data.metrics.seen_hosts} icon={Server} color="#8b5cf6" />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                  <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Traffic Volume (Events/Sec)</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={data.charts.volume}>
                        <defs>
                          <linearGradient id="colorEps" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={THEME.green} stopOpacity={0.3}/>
                            <stop offset="95%" stopColor={THEME.green} stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                        <XAxis dataKey="time" hide />
                        <YAxis hide />
                        <Tooltip content={<CustomTooltip />} />
                        <Area type="monotone" dataKey="eps" stroke={THEME.green} strokeWidth={2} fillOpacity={1} fill="url(#colorEps)" isAnimationActive={true} animationDuration={1000}/>
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                  <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Event Distribution</h3>
                  <div className="h-64 relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Security', value: data.metrics.counts.security },
                            { name: 'Auth Fail', value: data.metrics.counts.auth_fail },
                            { name: 'Logons', value: data.metrics.counts.logons },
                            { name: 'Sudo', value: data.metrics.counts.sudo }
                          ]}
                          cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value"
                        >
                          <Cell fill={COLORS.security} />
                          <Cell fill={COLORS.auth_fail} />
                          <Cell fill={COLORS.logons} />
                          <Cell fill={COLORS.sudo} />
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                        <Legend verticalAlign="bottom" height={36} iconType="circle" />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-white">{data.metrics.eps}</div>
                        <div className="text-[10px] text-gray-500 uppercase">EPS</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <RssFeed feeds={feeds} onRemoveFeed={removeFeed} />
                <CveFeed />
              </div>
              <div>
                <OverallAnalysis />
              </div>
              <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                  <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                    <Terminal size={16}/> Live Event Stream
                  </h3>
                  <EventStream logs={systemLogHistory} onHostClick={handleHostClick} />
              </div>
            </div>
          )}

          {/* --- TAB: HOST INVENTORY --- */}
          {activeTab === 'host_inventory' && (
             <HostInventory data={data} onHostClick={handleHostClick} />
          )}

          {/* --- TAB: BEHAVIORAL HIVE --- */}
          {activeTab === 'hive' && (
             <BehavioralHive data={data} onHostClick={handleHostClick} />
          )}

          {/* --- TAB: CYBER CITY --- */}
          {activeTab === 'city' && (
             <CyberCity data={data} onHostClick={handleHostClick} />
          )}

          {/* --- TAB: TRAFFIC TORUS --- */}
          {activeTab === 'torus' && (
             <TrafficTorus data={data} onHostClick={handleHostClick} />
          )}

          {/* --- TAB: NETFLOW GALAXY --- */}
          {activeTab === 'netflow_galaxy' && (
             <div className="h-[800px] bg-[#121212] border border-gray-800 rounded-lg shadow-lg">
                {/* Pass the buffered netflow data we are already collecting */}
                <NetflowGalaxy data={netflowBuffer} />
             </div>
          )}

          {/* --- TAB: galaxy --- */}
          {activeTab === 'galaxy' && (
            <div className="h-[800px] bg-[#121212] border border-gray-800 rounded-lg shadow-lg flex flex-col">
               {data.topology ? (
                   <Networkgalaxy 
                    data={data.topology} 
                    onNodeClick={handleHostClick} 
                    showExternal={showExternal}
                    setShowExternal={setShowExternal}
                    performanceMode={performanceMode}
                    setPerformanceMode={setPerformanceMode}
                   />
               ) : (
                   <div className="h-full flex items-center justify-center text-gray-500">
                       Waiting for galaxy data...
                   </div>
               )}
            </div>
          )}
          
          {/* --- TAB: DESTINATIONS --- */}
          {activeTab === 'destinations' && (
             <DestinationsMap destinations={data?.destinations || []} stats={data?.charts?.top_countries || []} />
          )}

          {/* --- TAB: ANOMALIES (System DNA) --- */}
          {(activeTab === 'anomalies') && (
            <ErrorBoundary>
              <div className="space-y-6">
                {/* 1. SAFETY CHECK: Check if data.anomalies exists */}
                {data?.anomalies ? (
                  <>
                    {(() => {
                        // Get history array safely
                        const history = data?.anomalies?.global_history || [];

                        // Grab the very last entry (most recent time slice)
                        const latestEntry = history.length > 0 ? history[history.length - 1] : null;

                        // Use the graph's value (avg_score) if available, otherwise fall back to 0
                        const liveScore = latestEntry && typeof latestEntry.avg_score === 'number' 
                          ? latestEntry.avg_score 
                          : 0;

                        return (
                          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <MetricCard 
                              label="Overall Anomaly Score" 
                              value={liveScore.toFixed(2)} 
                              icon={AlertTriangle} 
                              color={getAnomalyColor(liveScore)} 
                            />
                          </div>
                        );
                      })()}
                    <AnomalyLegend />
                        
                    {/* GLOBAL ANOMALY TREND */}
                    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                      <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Global Anomaly Trend</h3>
                      <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                          {/* FIX: Default to [] if global_history is missing */}
                          <AreaChart data={data.anomalies.global_history || []}>
                            <defs>
                              <linearGradient id="colorAnomaly" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor={THEME.red} stopOpacity={0.4}/>
                                <stop offset="40%" stopColor={THEME.orange} stopOpacity={0.2}/>
                                <stop offset="95%" stopColor={THEME.green} stopOpacity={0}/>
                              </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                            <XAxis dataKey="time" hide />
                            <YAxis domain={[0, Math.max(3, (data.anomalies.overall_anomaly_score || 0) + 2.5)]} />
                            <Tooltip content={<CustomTooltip />} />
                            <Area 
                              type="monotone" 
                              dataKey="avg_score" 
                              // FIX: Check if array exists AND has length before accessing index
                              stroke={getAnomalyColor(
                                (data.anomalies.global_history && data.anomalies.global_history.length > 0)
                                  ? data.anomalies.global_history[data.anomalies.global_history.length - 1].avg_score
                                  : 0
                              )} 
                              strokeWidth={2} 
                              fillOpacity={1} 
                              fill="url(#colorAnomaly)" 
                              isAnimationActive={true} 
                              animationDuration={1000}
                            />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                            
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      {/* Top Anomaly Hosts */}
                      {/* Top Anomaly Hosts - REPLACED WITH ROBUST TABLE */}
                      <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg flex flex-col h-64">
                        <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Top Anomaly Hosts</h3>
                                                  
                        <div className="flex-1 overflow-y-auto custom-scrollbar">
                          {data.anomalies?.top_hosts && data.anomalies.top_hosts.length > 0 ? (
                            <table className="w-full text-left text-xs">
                              <thead className="text-gray-500 border-b border-gray-800 sticky top-0 bg-[#121212]">
                                <tr>
                                  <th className="pb-2">Host</th>
                                  <th className="pb-2 text-right">Score</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-800">
                                {data.anomalies.top_hosts.map((host, i) => {
                                  // FIX: Check ALL possible property names for the score
                                  const rawScore = host.score ?? host.current_score ?? host.anomaly_score ?? 0;
                                  const numericScore = Number(rawScore) || 0;
                                
                                  return (
                                    <tr key={i} className="group hover:bg-gray-900 transition-colors cursor-pointer" onClick={() => handleHostClick(host.host)}>
                                      <td className="py-2 text-gray-300 font-mono truncate max-w-[150px]" title={host.host}>
                                        {host.host || "Unknown"}
                                        {/* DEBUG: Uncomment this to see exactly what keys are available */}
                                        {/* <span className="text-[9px] text-gray-600 block">{Object.keys(host).join(', ')}</span> */}
                                      </td>
                                      <td className="py-2 text-right">
                                        <div className="flex items-center justify-end gap-2">
                                          <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                            <div 
                                              className="h-full rounded-full transition-all duration-500" 
                                              style={{ 
                                                width: `${Math.min((numericScore / 10) * 100, 100)}%`,
                                                backgroundColor: getAnomalyColor(numericScore)
                                              }}
                                            ></div>
                                          </div>
                                          <span className={`font-bold ${numericScore > 5 ? 'text-red-500' : 'text-gray-400'}`}>
                                            {numericScore.toFixed(2)}
                                          </span>
                                        </div>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          ) : (
                            <div className="h-full flex flex-col items-center justify-center text-gray-600 italic">
                              <Server size={32} className="mb-2 opacity-20"/>
                              No Host Anomalies
                            </div>
                          )}
                        </div>
                      </div>
                              
                      {/* Major Anomaly Events */}
                      <div className="lg:col-span-2 bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                        <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                          <Terminal size={16}/> Major Anomaly Events
                        </h3>
                        <MajorAnomalyEventTable logs={consolidatedEvents} onHostClick={handleHostClick} />
                      </div>
                    </div>
                              
                    {selectedAnomaly && (
                      <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                        <div className="flex justify-between items-center mb-4">
                          <h3 className="text-sm font-bold text-gray-400 uppercase flex items-center gap-2">Events for {selectedAnomaly.host}</h3>
                          <button onClick={() => setSelectedAnomaly(null)} className="hover:text-white"><X size={12}/></button>
                        </div>
                        <EventStream logs={selectedAnomaly.logs} onHostClick={handleHostClick} />
                      </div>
                    )}

                    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                      <div className="flex justify-between items-center mb-4">
                        <h3 className="text-sm font-bold text-gray-400 uppercase flex items-center gap-2">Anomaly Event Stream (Score &gt; 0.0)</h3>
                      </div>
                      <EventStream logs={systemLogHistory.filter(log => log.anomaly_score > 0.0)} onHostClick={handleHostClick} />
                    </div>
                  </>
                ) : (
                  // 2. FALLBACK: Data not ready yet
                  <div className="h-96 flex flex-col items-center justify-center text-gray-500">
                     <AlertTriangle size={48} className="mb-4 opacity-50 text-orange-500" />
                     <span>Waiting for Anomaly Data Pipeline...</span>
                  </div>
                )}
              </div>
            </ErrorBoundary>
          )}

          {/* --- TAB: NETFLOW DNA (With Overall Score Header) --- */}
          {activeTab === 'dfp' && (
            <div className="space-y-6">
              
              {/* 1. NEW: NETWORK SCORECARD HEADER */}
              {(() => {
                  // Calculate live stats from the buffer
                  const scores = netflowBuffer.map(d => d.y);
                  const avgScore = scores.length > 0 
                      ? (scores.reduce((a, b) => a + b, 0) / scores.length) 
                      : 0;
                  const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
                  const criticalCount = netflowBuffer.filter(d => d.y > 5.0).length;

                  return (
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <MetricCard 
                            label="Overall Network Anomaly Score" 
                            value={avgScore.toFixed(2)} 
                            icon={Activity} 
                            color={getAnomalyColor(avgScore)} 
                        />
                        <MetricCard 
                            label="Peak Deviation" 
                            value={maxScore.toFixed(2)} 
                            icon={Zap} 
                            color={getAnomalyColor(maxScore)} 
                        />
                        <MetricCard 
                            label="Critical Events (Buffered)" 
                            value={criticalCount} 
                            icon={AlertTriangle} 
                            color={criticalCount > 0 ? THEME.red : THEME.green} 
                        />
                        <MetricCard 
                            label="Active Flows Analyzed" 
                            value={netflowBuffer.length} 
                            icon={Share2} 
                            color={THEME.blue} 
                        />
                    </div>
                  );
              })()}

              {/* 2. EXISTING CHARTS LOGIC */}
              {(() => {
                 const derivedCauses = netflowBuffer.reduce((acc, item) => {
                    const cause = item.cause || 'Unknown';
                    const found = acc.find(a => a.name === cause);
                    if (found) found.value++;
                    else acc.push({ name: cause, value: 1 });
                    return acc;
                 }, []).sort((a, b) => b.value - a.value);
                 
                 return (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* SCATTER CHART */}
                    <div className="lg:col-span-2 bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg flex flex-col">
                      <div className="flex justify-between items-start mb-4">
                          <div>
                              <h3 className="text-sm font-bold text-gray-400 uppercase flex items-center gap-2">
                                <Fingerprint size={16} className="text-blue-500"/> 
                                Host vs Destination Port Map
                              </h3>
                              <div className="text-[10px] text-gray-500 mt-1">
                                 Displaying last {netflowBuffer.length} analyzed flows (Buffered)
                              </div>
                          </div>
                      </div>

                      <div className="h-80">
                        <ResponsiveContainer width="100%" height="100%">
                          <ScatterChart margin={{ top: 20, right: 20, bottom: 60, left: 20 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                            <XAxis 
                                type="category" dataKey="host" name="Host IP" stroke="#666" 
                                allowDuplicatedCategory={false}
                                tick={{ fontSize: 10, fill: '#666' }}
                                interval={0} angle={-45} textAnchor="end" height={60}
                            />
                            <YAxis 
                                type="number" dataKey="port" name="Dest Port" stroke="#666" 
                                label={{ value: 'Destination Port', angle: -90, position: 'insideLeft', fill: '#666' }} 
                            />
                            <Tooltip cursor={{ strokeDasharray: '3 3' }} content={({ active, payload }) => {
                              if (active && payload && payload.length) {
                                const data = payload[0].payload;
                                return (
                                  <div className="bg-black border border-gray-700 p-2 rounded shadow-xl text-xs z-50">
                                    <div className="text-green-400 font-bold mb-1">{data.host}</div>
                                    <div className="mb-1 text-gray-300">
                                        Score: <span className={data.y > 2 ? "text-red-400 font-bold" : "text-white"}>{data.y.toFixed(4)}</span>
                                    </div>
                                    <div className="grid grid-cols-2 gap-x-4 border-t border-gray-800 pt-1">
                                        <span className="text-gray-500">Bytes:</span> <span className="text-white text-right">{data.bytes}</span>
                                        <span className="text-gray-500">Port:</span> <span className="text-white text-right">{data.port}</span>
                                    </div>
                                    <div className="text-orange-400 mt-2 italic">{data.cause}</div>
                                  </div>
                                );
                              }
                              return null;
                            }} />
                            <Scatter 
                                name="Anomalies"
                                data={netflowBuffer.filter(d => d.y > 5.0)} 
                                fill="#ef4444" 
                            >
                              {netflowBuffer
                                .filter(d => d.y > 5.0) 
                                .map((entry, index) => (
                                <Cell key={`cell-${index}`} fill="#ef4444" />
                              ))}
                            </Scatter>
                          </ScatterChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                                        
                    {/* PIE CHART */}
                    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                      <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Anomaly Attribution</h3>
                      <div className="h-64">
                          <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                              <Pie 
                                data={derivedCauses} 
                                cx="50%" cy="50%" 
                                innerRadius={60} outerRadius={80} 
                                paddingAngle={5} 
                                dataKey="value"
                              >
                                {derivedCauses.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={[THEME.blue, THEME.orange, THEME.red, THEME.green][index % 4]} />
                                ))}
                              </Pie>
                              <Tooltip content={<CustomTooltip />} />
                              <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{fontSize: '10px'}} />
                            </PieChart>
                          </ResponsiveContainer>
                      </div>
                      <div className="mt-4 p-3 bg-blue-900/10 rounded border border-blue-900/30">
                          <h4 className="text-xs font-bold text-blue-400 mb-1">AI Insight</h4>
                          <p className="text-[10px] text-gray-400">
                              Based on {netflowBuffer.length} buffered flows, the AutoEncoder is flagging 
                              <span className="text-white font-bold"> {(derivedCauses?.[0]?.name) || "N/A"} </span>
                              as the primary anomaly driver.
                          </p>
                      </div>
                    </div>
                  </div>
                 );
              })()}
                          
              {/* DATA TABLE */}
              <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                  <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                      <Activity size={16}/> Netflow Anomaly Stream (192.168.0.0/27)
                  </h3>
                  <EventStream logs={netflowLogBuffer} onHostClick={handleHostClick} /> 
              </div>
            </div>
          )}

          {/* --- TAB: USER ACTIVITY --- */}
          {activeTab === 'user' && (
            <div className="space-y-6">
               <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                 
                 {/* LEFT COLUMN: USER LIST */}
                 <div className="bg-[#121212] border border-gray-800 rounded-lg p-0 flex flex-col h-[800px]">
                    <div className="p-5 border-b border-gray-800">
                      <h3 className="text-sm font-bold text-gray-400 uppercase">Active User Registry</h3>
                      <div className="text-xs text-gray-600 mt-1">Select a user to view forensics</div>
                    </div>
                    <div className="flex-1 overflow-y-auto custom-scrollbar">
                      <table className="w-full text-sm text-left">
                        <thead className="text-xs text-gray-500 uppercase bg-[#0a0a0a] sticky top-0">
                          <tr>
                            <th className="px-4 py-3">User</th>
                            <th className="px-4 py-3 text-right">Events</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                          {data.tables.users.map((u, i) => (
                            <tr 
                              key={i} 
                              onClick={() => setSelectedUser(u)}
                              className={`cursor-pointer transition-colors ${selectedUser?.user === u.user ? 'bg-[#1A1A1A] border-l-2 border-green-500' : 'hover:bg-gray-900/50'}`}
                            >
                              <td className="px-4 py-3 font-medium text-white flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-full ${selectedUser?.user === u.user ? 'bg-green-500' : 'bg-gray-700'}`}></div>
                                {u.user}
                              </td>
                              <td className="px-4 py-3 text-right text-gray-500 font-mono">{u.count}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                 </div>

                 {/* RIGHT COLUMN: FORENSICS PANEL */}
                 <div className="lg:col-span-2 flex flex-col gap-6 h-[800px] overflow-y-auto custom-scrollbar">
                    
                    {/* BURST VISUALIZATION */}
                    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                        <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                            <Zap size={16} className="text-yellow-500" /> Live User Velocity (Burst Detection - Last 60s)
                        </h3>
                        <div className="h-40">
                            {burstStats.length > 0 ? (
                              <ResponsiveContainer width="100%" height="100%">
                                  <BarChart 
                                      layout="vertical" 
                                      data={burstStats}
                                      onClick={(data) => {
                                        if(data && data.activeLabel) {
                                          const target = data.tables?.users?.find(u => u.user === data.activeLabel);
                                          if(target) setSelectedUser(target);
                                          else setSelectedUser({ user: data.activeLabel, count: 0, last_seen: 'Now' });
                                        }
                                      }}
                                      className="cursor-pointer"
                                  >
                                      <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
                                      <XAxis type="number" hide />
                                      <YAxis dataKey="user" type="category" width={100} tick={{fontSize: 11, fill: '#999'}} />
                                      <Tooltip cursor={{fill: '#ffffff10'}} contentStyle={{backgroundColor: '#000', borderColor: '#333', color: '#fff'}} />
                                      <Bar dataKey="value" barSize={15} radius={[0, 4, 4, 0]}>
                                          {burstStats.map((entry, index) => (
                                              <Cell key={`cell-${index}`} fill={entry.value > 20 ? THEME.red : entry.value > 10 ? THEME.orange : THEME.blue} />
                                          ))}
                                      </Bar>
                                  </BarChart>
                              </ResponsiveContainer>
                            ) : (
                              <div className="h-full flex flex-col items-center justify-center text-gray-600">
                                  <Activity size={32} className="mb-2 opacity-20" />
                                  <span className="text-xs">No active bursts detected</span>
                              </div>
                            )}
                        </div>
                    </div>

                    {selectedUser ? (
                      <>
                        {/* User Header Card */}
                        <div className="bg-[#121212] border border-gray-800 rounded-lg p-6">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-4">
                                  <div className="p-3 bg-green-500/10 rounded-full">
                                    <Users size={32} className="text-green-500" />
                                  </div>
                                  <div>
                                    <h2 className="text-2xl font-bold text-white">{selectedUser.user}</h2>
                                    <div className="flex items-center gap-4 text-xs text-gray-400 mt-1">
                                      <span className="flex items-center gap-1"><Clock size={12}/> Last Seen: {selectedUser.last_seen}</span>
                                      <span className="flex items-center gap-1"><Monitor size={12}/> Last Host: {selectedUser.last_host}</span>
                                    </div>
                                  </div>
                              </div>
                              <div className="text-right">
                                <div className="text-sm text-gray-500 uppercase font-bold">Total Events</div>
                                <div className="text-3xl font-mono text-white">{selectedUser.count}</div>
                              </div>
                            </div>
                        </div>

                        {/* Charts Row */}
                        <div className="grid grid-cols-2 gap-6">
                            <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 h-64">
                                <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                    <Activity size={16}/> Activity Volume (Live Capture)
                                </h3>
                                <div className="h-40">
                                    {/* FIX: Check if we actually have recent data for this user */}
                                    {userStats.activity.length > 0 ? (
                                        <ResponsiveContainer width="100%" height="100%">
                                            <AreaChart data={userStats.activity}>
                                                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                                                <XAxis dataKey="time" hide />
                                                <Tooltip content={<CustomTooltip />} />
                                                <Area type="monotone" dataKey="count" stroke={THEME.green} fill={THEME.green} fillOpacity={0.2} />
                                            </AreaChart>
                                        </ResponsiveContainer>
                                    ) : (
                                        <div className="h-full flex flex-col items-center justify-center text-gray-600">
                                            <Activity size={32} className="mb-2 opacity-20" />
                                            <span className="text-xs font-mono">No activity in current session buffer</span>
                                            <span className="text-[9px] text-gray-700 mt-1">(Chart only shows live data received since page load)</span>
                                        </div>
                                    )}
                                </div>
                            </div>

                            <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 h-64">
                                <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                    <PieIcon size={16}/> Event Breakdown
                                </h3>
                                <div className="h-40">
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie 
                                                data={userStats.categories} 
                                                dataKey="value" 
                                                cx="50%" cy="50%" 
                                                innerRadius={40} 
                                                outerRadius={60}
                                            >
                                                {userStats.categories.map((entry, index) => (
                                                    <Cell key={`cell-${index}`} fill={COLORS[entry.name] || COLORS.other} />
                                                ))}
                                            </Pie>
                                            <Tooltip content={<CustomTooltip />} />
                                            <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{fontSize: '10px'}} />
                                        </PieChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>
                        </div>

                        {/* SYSTEM PIVOT AREA */}
                        <div className="flex flex-col gap-4">
                            {/* 1. Clickable Access List */}
                            <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 flex-1">
                                <h3 className="text-sm font-bold text-gray-400 uppercase mb-1 flex items-center gap-2">
                                  <Network size={16} /> Accessed Systems ({selectedUser.hosts ? selectedUser.hosts.length : 0})
                                </h3>
                                <div className="text-[10px] text-gray-500 mb-3">Click a system to see other users</div>
                                
                                <div className="overflow-y-auto custom-scrollbar max-h-48 bg-[#0a0a0a] rounded border border-gray-800 p-4">
                                    {selectedUser.hosts && selectedUser.hosts.length > 0 ? (
                                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                        {selectedUser.hosts.map((host, i) => (
                                          <div 
                                            key={i} 
                                            onClick={() => setSelectedSystem(host === selectedSystem ? null : host)}
                                            className={`flex items-center gap-3 p-2 rounded border text-xs font-mono transition-all cursor-pointer
                                              ${host === selectedSystem 
                                                ? 'bg-[#1a1a1a] border-blue-500 text-white shadow-lg' 
                                                : 'bg-[#151515] border-gray-800 text-gray-300 hover:border-gray-600'
                                              }`}
                                           >
                                            <Server size={14} className={host === selectedSystem ? 'text-blue-500' : 'text-gray-600'} />
                                            <span className="truncate flex-1">{host}</span>
                                            <button 
                                              onClick={(e) => { e.stopPropagation(); handleHostClick(host); }}
                                              className="p-1 hover:bg-white/10 rounded transition-colors text-gray-500 hover:text-blue-400"
                                              title="View Host Details"
                                            >
                                              <ExternalLink size={12} />
                                            </button>
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <div className="h-24 flex flex-col items-center justify-center text-gray-600 italic">
                                        <Server size={48} className="mb-4 opacity-20" />
                                        No distinct hosts recorded.
                                      </div>
                                    )}
                                </div>
                            </div>

                            {/* 2. System Inspector Panel (Shows on Selection) */}
                            {selectedSystem && (
                                <div className="bg-[#121212] border border-blue-500/50 rounded-lg p-5 animate-in slide-in-from-bottom-4 fade-in duration-300">
                                    <div className="flex justify-between items-start mb-4 border-b border-gray-800 pb-2">
                                      <div>
                                        <h3 className="text-blue-500 font-bold text-sm uppercase flex items-center gap-2">
                                          <Share2 size={16}/> Users Accessing {selectedSystem}
                                        </h3>
                                        <div className="text-[10px] text-gray-500 mt-1">
                                          {usersOnSystem.length > 1 ? `${usersOnSystem.length} concurrent users found` : 'Only this user found'}
                                        </div>
                                      </div>
                                      <button onClick={() => setSelectedSystem(null)} className="text-gray-500 hover:text-white"><X size={16}/></button>
                                    </div>

                                    <div className="overflow-x-auto pb-2">
                                      <div className="flex gap-2">
                                        {usersOnSystem.map((u, i) => (
                                          <button
                                            key={i}
                                            onClick={() => setSelectedUser(u)}
                                            className={`flex flex-col items-center p-3 rounded border min-w-[100px] transition-colors
                                              ${u.user === selectedUser.user 
                                                ? 'bg-blue-900/20 border-blue-500 text-white' 
                                                : 'bg-[#1A1A1A] border-gray-700 text-gray-400 hover:bg-[#222] hover:text-white'
                                              }`}
                                          >
                                            <div className="p-2 bg-black/50 rounded-full mb-2">
                                              <Users size={16} className={u.user === selectedUser.user ? 'text-blue-400' : 'text-gray-600'} />
                                            </div>
                                            <span className="text-xs font-bold truncate max-w-[90px]">{u.user}</span>
                                            <span className="text-[9px] opacity-60 mt-1">{u.count} events</span>
                                          </button>
                                        ))}
                                      </div>
                                    </div>
                                </div>
                            )}
                        </div>
                      </>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-gray-600">
                        <Users size={64} className="mb-4 opacity-20" />
                        <p className="text-lg font-medium">User Forensics</p>
                        <p className="text-sm mt-2">Select a user from the registry to view access history.</p>
                      </div>
                    )}
                 </div>

               </div>
            </div>
          )}

          {/* --- TAB: NETWORK & FIREWALL --- */}
          {activeTab === 'network' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-[#121212] border border-gray-800 rounded-lg p-0 overflow-hidden h-[500px]">
                  {/* --- OPTIMIZED MAP COMPONENT --- */}
                  <ComposableMap projectionConfig={{ scale: 200 }} width={800} height={500} style={{ width: "100%", height: "100%" }}>
                    <Geographies geography={GEO_URL}>
                      {({ geographies }) => geographies.map((geo) => ( 
                        <Geography 
                          key={geo.rsmKey} 
                          geography={geo} 
                          fill="#1a1a1a" 
                          stroke="#333" 
                          strokeWidth={0.5} 
                          style={{ default: { outline: "none" }, hover: { fill: "#333", outline: "none" }, pressed: { outline: "none" }}}
                        /> 
                      ))}
                    </Geographies>
                    {/* Render aggregated markers instead of raw points */}
                    {mapMarkers.map((marker, i) => ( 
                      <Marker key={`${marker.lat}-${marker.lon}-${i}`} coordinates={[marker.lon, marker.lat]}> 
                        <circle 
                          // Scale radius based on attack count (logarithmic)
                          r={4 + Math.log(marker.count) * 2} 
                          fill={marker.isBlocked ? THEME.red : THEME.green} 
                          stroke="#000" 
                          strokeWidth={1} 
                          // Only animate if map is not crowded to save CPU
                          className={mapMarkers.length < 50 ? "animate-pulse opacity-80" : "opacity-80"} 
                        /> 
                          {/* Optional text counter for high volume nodes */}
                          {marker.count > 1 && (
                             <text textAnchor="middle" y={-8} style={{fontFamily: 'sans-serif', fill: '#fff', fontSize: '10px', fontWeight: 'bold', pointerEvents: 'none'}}>
                                {marker.count}
                             </text>
                          )}
                      </Marker> 
                    ))}
                  </ComposableMap>
                </div>
                <div className="space-y-6 flex flex-col">
                  <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 flex-1 h-60">
                    <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Top Attacking Countries</h3>
                    <div className="h-40">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={persistentCharts.topAttackCountries}>
                          <XAxis type="number" hide /><YAxis dataKey="name" type="category" width={80} tick={{fontSize: 10, fill: '#888'}} interval={0} /><Tooltip content={<CustomTooltip />} /><Bar dataKey="count" fill={THEME.red} radius={[0, 4, 4, 0]} barSize={12} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 flex-1 h-60">
                    <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Top Attacked Hosts</h3>
                    <div className="h-40">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={persistentCharts.topHosts}>
                          <XAxis type="number" hide /><YAxis dataKey="host" type="category" width={80} tick={{fontSize: 10, fill: '#888'}} interval={0} /><Tooltip content={<CustomTooltip />} /><Bar dataKey="total" fill={THEME.orange} radius={[0, 4, 4, 0]} barSize={12} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                    <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Traffic Verdict Timeline (Live)</h3>
                    <div className="h-40">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={firewallStats.timeline}>
                           <defs>
                             <linearGradient id="gradGreen" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={THEME.green} stopOpacity={0.8}/><stop offset="95%" stopColor={THEME.green} stopOpacity={0}/></linearGradient>
                             <linearGradient id="gradRed" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={THEME.red} stopOpacity={0.8}/><stop offset="95%" stopColor={THEME.red} stopOpacity={0}/></linearGradient>
                           </defs>
                           <XAxis dataKey="time" hide />
                           <YAxis tick={{fontSize: 10, fill: '#666'}} axisLine={false} tickLine={false} width={30} />
                           <Tooltip content={<CustomTooltip />} />
                           <Area type="monotone" dataKey="Allow" stroke={THEME.green} fill="url(#gradGreen)" />
                           <Area type="monotone" dataKey="Block" stroke={THEME.red} fill="url(#gradRed)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                    <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Port Protocol Activity (Live)</h3>
                    <div className="h-40">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={firewallStats.topPorts}>
                          <XAxis type="number" hide /><YAxis dataKey="port" type="category" width={50} tick={{fontSize: 10, fill: '#888'}} /><Tooltip content={<CustomTooltip />} /><Bar dataKey="Allow" stackId="a" fill={THEME.green} barSize={12} /><Bar dataKey="Block" stackId="a" fill={THEME.red} radius={[0, 4, 4, 0]} barSize={12} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
              </div>
              <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                  <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2"><Activity size={16} className="text-red-500"/> Firewall Activity</h3>
                  <NetworkLogTable logs={firewallHistory} onHostClick={handleHostClick} />
              </div>
            </div>
          )}

                    {/* --- TAB: HOST FORENSICS --- */}
                    {activeTab === 'host' && (
                      <div className="space-y-6">
                        <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                          <div className="flex justify-between items-center mb-4">
                            <h3 className="text-sm font-bold text-gray-400 uppercase flex items-center gap-2"><MousePointerClick size={16} /> Top Noisy Hosts</h3>
                            <div className="text-[10px] text-gray-500">Click a bar to filter events</div>
                          </div>
                          <div className="h-64">
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={persistentCharts.topHosts} className="cursor-pointer" onClick={(data) => { if (data && data.activeLabel) { setFocusHost(data.activeLabel); } }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} /><XAxis dataKey="host" tick={{fontSize: 10, fill: '#888'}} interval={0} /><YAxis /><Tooltip content={<CustomTooltip />} /><Bar dataKey="total" fill={THEME.green} barSize={40} />
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                        <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                          <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Hosts with Notable Events</h3>
                          <div className="h-64">
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={persistentCharts.topHosts} className="cursor-pointer" onClick={(data) => { if (data && data.activeLabel) { setFocusHost(data.activeLabel); } }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} /><XAxis dataKey="host" tick={{fontSize: 10, fill: '#888'}} interval={0} /><YAxis /><Tooltip content={<CustomTooltip />} /><Bar dataKey="security" fill={THEME.red} barSize={40} />
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-6">
  
                          {/* TOP USERS CHART */}
                          <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                            <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Top Sudo Users</h3>
                            <div className="h-64">
                              <ResponsiveContainer width="100%" height="100%">
                                {/* Fix: Optional chaining and fallback */}
                                <BarChart layout="vertical" data={data?.sudo_stats?.top_users || []}>
                                  <XAxis type="number" hide />
                                  {/* Fix: dataKey="name" */}
                                  <YAxis dataKey="name" type="category" width={80} tick={{fontSize: 10, fill: '#888'}} interval={0} />
                                  <Tooltip content={<CustomTooltip />} />
                                  {/* Fix: dataKey="value" */}
                                  <Bar dataKey="value" fill={THEME.blue} radius={[0, 4, 4, 0]} barSize={12} />
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>

                          {/* TOP HOSTS CHART */}
                          <div className="bg-[#121212] border border-gray-800 rounded-lg p-5">
                            <h3 className="text-sm font-bold text-gray-400 uppercase mb-4">Top Sudo Hosts</h3>
                            <div className="h-64">
                              <ResponsiveContainer width="100%" height="100%">
                                {/* Fix: Optional chaining and fallback */}
                                <BarChart layout="vertical" data={data?.sudo_stats?.top_hosts || []}>
                                  <XAxis type="number" hide />
                                  {/* Fix: dataKey="name" */}
                                  <YAxis dataKey="name" type="category" width={80} tick={{fontSize: 10, fill: '#888'}} interval={0} />
                                  <Tooltip content={<CustomTooltip />} />
                                  {/* Fix: dataKey="value" */}
                                  <Bar dataKey="value" fill={THEME.blue} radius={[0, 4, 4, 0]} barSize={12} />
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>

                        </div>
          
                        <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                           <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2"><Terminal size={16}/> Sudo Command Stream</h3>
                           <SudoLogTable logs={data.tables.sudo_commands} onHostClick={handleHostClick} />
                        </div>
                        <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
                           <div className="flex justify-between items-center mb-4">
                             <h3 className="text-sm font-bold text-gray-400 uppercase flex items-center gap-2"><Terminal size={16}/> Host Event Stream</h3>
                             {focusHost && ( <div className="flex items-center gap-2 px-2 py-1 bg-green-900/20 border border-green-900 rounded text-green-500 text-xs"><span>Filtered: <strong>{focusHost}</strong></span><button onClick={() => setFocusHost('')} className="hover:text-white"><X size={12}/></button></div> )}
                           </div>
                           <EventStream logs={systemLogHistory} defaultSearch={focusHost} onHostClick={handleHostClick} />
                        </div>
                      </div>
                    )}
          {/* --- TAB: NETBOX --- */}
          {activeTab === 'netbox' && (
            <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
              <NetboxVulnerabilities />
            </div>
          )}
          {/* --- TAB: RAW --- */}
          {(activeTab === 'raw') && (
            <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
              <EventStream logs={systemLogHistory} />
            </div>
          )}

        </div>
        <HostDetailOverlay 
          host={selectedHost} 
          onClose={() => setSelectedHost(null)} 
          data={data} 
          onHostClick={handleHostClick}
        />
        <ChatWidget 
          dashboardData={data} 
          isOpen={isChatOpen}
          setIsOpen={setIsChatOpen}
          messages={chatMessages}
          setMessages={setChatMessages}
        />
      </main>
    </div>
  );
}

// --- SUB-COMPONENTS ---

const NavButton = ({ id, label, icon: Icon, activeTab, setTab }) => (
  <button onClick={() => setTab(id)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${activeTab === id ? 'bg-[#1A1A1A] text-white border-l-4 border-green-500 shadow-lg' : 'text-gray-500 hover:bg-[#111] hover:text-gray-300 border-l-4 border-transparent'}`}><Icon size={18} className={activeTab === id ? 'text-green-500' : 'text-gray-600'} />{label}</button>
);

const CollapsibleNavSection = ({ label, icon: Icon, children, activeTab, childIds = [] }) => {
  const isAnyChildActive = useMemo(() => childIds.includes(activeTab), [activeTab, childIds]);
  const [isOpen, setIsOpen] = useState(isAnyChildActive);
  
  useEffect(() => {
    if (isAnyChildActive) setIsOpen(true);
  }, [isAnyChildActive]);

  return (
    <div className="space-y-1">
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between px-4 py-3 rounded-md text-sm font-bold transition-all duration-200 ${isOpen ? 'text-gray-300' : 'text-gray-500'} hover:bg-[#111] hover:text-gray-300`}
      >
        <div className="flex items-center gap-3">
          <Icon size={18} className={isAnyChildActive ? 'text-green-500' : 'text-gray-600'} />
          {label}
        </div>
        <div className="text-gray-600">
          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </button>
      {isOpen && (
        <div className="pl-2 space-y-1">
          {children}
        </div>
      )}
    </div>
  );
};

const MetricCard = ({ label, value, icon: Icon, color }) => (
  <div className="bg-[#121212] p-5 rounded-lg border border-gray-800 relative overflow-hidden group hover:border-gray-700 transition-colors"><div className="absolute top-0 left-0 w-1 h-full" style={{ backgroundColor: color }}></div><div className="flex justify-between items-start relative z-10"><div><div className="text-gray-500 text-[10px] font-bold uppercase tracking-wider mb-1">{label}</div><div className="text-2xl font-bold text-white font-mono">{value}</div></div><div className="p-2 rounded bg-[#0a0a0a] text-gray-400 group-hover:text-white transition-colors"><Icon size={20} /></div></div></div>
);

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return ( <div className="bg-[#0a0a0a] border border-gray-800 p-3 rounded shadow-xl text-xs z-50"><div className="text-gray-400 font-bold mb-2">{label || 'Details'}</div>{payload.map((entry, index) => ( <div key={index} className="flex items-center gap-2 mb-1" style={{ color: entry.color }}><div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></div><span className="uppercase font-bold">{entry.name}:</span><span className="text-white font-mono">{entry.value}</span></div> ))}</div> );
  }
  return null;
};

const LoadingScreen = ({ status }) => (
  <div className="h-screen w-screen bg-black flex flex-col items-center justify-center text-green-500 font-mono"><Activity size={48} className="animate-bounce mb-4" /><div className="text-xl tracking-widest">ESTABLISHING UPLINK</div><div className="text-xs text-gray-600 mt-2">{status}</div></div>
);

const HostDetailOverlay = ({ host, onClose, data, onHostClick }) => {
  if (!host) return null;

  const [realHistory, setRealHistory] = useState([]);
  const [anomalyLogs, setAnomalyLogs] = useState([]);
  const [realPorts, setRealPorts] = useState([]);
  const [hoveredPoint, setHoveredPoint] = useState(null);

  useEffect(() => {
    if (!host) return;
    setHoveredPoint(null); // Reset on host change
    setRealPorts([]); // Reset ports
    setAnomalyLogs([]); // Reset logs
    
    // Fetch real history from API
    const fetchHistory = async () => {
        try {
            // Use relative path to go through nginx proxy (/api/host/...)
            const response = await fetch(`/api/host/${encodeURIComponent(host.id)}/history`);
            if (response.ok) {
                const history = await response.json();
                setRealHistory(history);
            }
        } catch (e) {
            console.error("Failed to fetch host history:", e);
        }
    };

    // Fetch real ports from API
    const fetchPorts = async () => {
        try {
            const response = await fetch(`/api/host/${encodeURIComponent(host.id)}/ports`);
            if (response.ok) {
                const ports = await response.json();
                setRealPorts(ports);
            }
        } catch (e) {
            console.error("Failed to fetch host ports:", e);
        }
    };

    // Fetch Anomaly Logs
    const fetchAnomalyLogs = async () => {
        try {
            const response = await fetch(`/api/host/${encodeURIComponent(host.id)}/anomaly-logs`);
            if (response.ok) {
                const logs = await response.json();
                setAnomalyLogs(logs);
            }
        } catch (e) {
            console.error("Failed to fetch host anomaly logs:", e);
        }
    };

    fetchHistory();
    fetchPorts();
    fetchAnomalyLogs();
  }, [host]);

  // Use the hovered point's reason, or fallback to the host's current reason
  const activeReason = hoveredPoint?.reason || host.reason || "Anomalous activity detected via DFP engine.";
  const activeScore = hoveredPoint?.score ?? host.score;

  // Process data for the overlay
  const stats = useMemo(() => {
    // 1. Bandwidth (Using real counters from host object)
    const bandwidth = { 
        up: host.sent || 0, 
        down: host.received || 0 
    };

    // 2. Ports (Using real data from API, with fallback to scatter)
    const ports = new Set(realPorts);
    if (data?.netflow?.scatter) {
        data.netflow.scatter.filter(f => f.host === host.id).forEach(f => ports.add(`${f.port}/TCP`));
    }

    // 3. Peer Connections (Resolved with Source Data)
    const connections = [];
    if (data?.topology?.links && data?.topology?.nodes) {
        data.topology.links.forEach(link => {
            const srcId = typeof link.source === 'object' ? link.source.id : link.source;
            const dstId = typeof link.target === 'object' ? link.target.id : link.target;
            
            let peerId = null;
            if (srcId === host.id) peerId = dstId;
            else if (dstId === host.id) peerId = srcId;

            if (peerId && !connections.find(c => c.id === peerId)) {
                const peerNode = data.topology.nodes.find(n => n.id === peerId);
                connections.push({
                    id: peerId,
                    sources: peerNode?.sources || []
                });
            }
        });
    }

    return { bandwidth, ports, connections };
  }, [host, data]);

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleExportConnections = () => {
    if (!stats.connections.length) return;
    const content = "Host IP\n" + stats.connections.map(c => c.id).join("\n");
    const blob = new Blob([content], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `connections-${host.id}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const PeerSourceBadges = ({ sources }) => {
    const hasLogs = sources.includes('syslog');
    const hasNetflow = sources.includes('netflow_v9') || sources.includes('netflow');
    
    return (
      <div className="flex gap-1 ml-auto mr-2">
        {hasLogs && (
          <span className="px-1 py-0.5 rounded-sm bg-blue-500/10 border border-blue-500/20 text-[8px] text-blue-400 font-bold uppercase" title="Learned from Logs">L</span>
        )}
        {hasNetflow && (
          <span className="px-1 py-0.5 rounded-sm bg-purple-500/10 border border-purple-500/20 text-[8px] text-purple-400 font-bold uppercase" title="Learned from Netflow">N</span>
        )}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-300" onClick={onClose}>
      <div 
        className="w-full max-w-2xl h-full bg-[#0a0a0a] border-l border-gray-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-500"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6 border-b border-gray-800 flex justify-between items-center bg-[#121212]">
          <div className="flex items-center gap-4">
            <div className={`p-3 rounded-full bg-opacity-10`} style={{ backgroundColor: getAnomalyColor(host.score) }}>
              <Shield size={32} style={{ color: getAnomalyColor(host.score) }} />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-white leading-tight">{host.name || host.id}</h3>
              <div className="flex items-center gap-3 text-xs text-gray-500 mt-1">
                <span className="font-mono bg-gray-900 px-2 py-0.5 rounded border border-gray-800">{host.id}</span>
                <span className="flex items-center gap-1"><GlobeIcon size={12}/> {host.site_name || 'Global'}</span>
                <div className="flex gap-1 ml-2">
                  {host.sources?.includes('syslog') && (
                    <span className="px-1.5 py-0.5 rounded-sm bg-blue-500/10 border border-blue-500/20 text-[9px] text-blue-400 font-bold uppercase">Logs</span>
                  )}
                  {(host.sources?.includes('netflow_v9') || host.sources?.includes('netflow')) && (
                    <span className="px-1.5 py-0.5 rounded-sm bg-purple-500/10 border border-purple-500/20 text-[9px] text-purple-400 font-bold uppercase">Netflow</span>
                  )}
                </div>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-gray-500 hover:text-white hover:bg-gray-800 rounded-full transition-all">
            <X size={24} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-8 custom-scrollbar">
          {activeScore > 0 && activeReason && (
            <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-lg">
              <div className="text-[10px] uppercase font-bold text-red-500 mb-1 flex items-center justify-between">
                <span className="flex items-center gap-2"><AlertTriangle size={12} /> {hoveredPoint ? 'Historic Anomaly Reason' : 'Current Anomaly Reason'}</span>
                {hoveredPoint && <span className="font-mono text-gray-500">{hoveredPoint.time}</span>}
              </div>
              <div className="text-sm text-gray-200 font-medium italic">
                "{activeReason}"
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-[#121212] p-4 rounded-lg border border-gray-800">
              <div className="text-[10px] uppercase font-bold text-gray-500 mb-1">{hoveredPoint ? 'Snapshot Risk' : 'Current Risk'}</div>
              <div className="text-3xl font-black font-mono" style={{ color: getAnomalyColor(activeScore) }}>
                {activeScore?.toFixed(2) || '0.00'}
              </div>
            </div>
            <div className="bg-[#121212] p-4 rounded-lg border border-gray-800">
              <div className="text-[10px] uppercase font-bold text-gray-500 mb-1">Asset Health</div>
              <div className="text-3xl font-black font-mono" style={{ color: getAnomalyColor(activeScore) }}>
                {Math.max(0, 100 - (activeScore * 10)).toFixed(0)}%
              </div>
            </div>
            <div className="bg-[#121212] p-4 rounded-lg border border-gray-800">
              <div className="text-[10px] uppercase font-bold text-gray-500 mb-1">Total Events</div>
              <div className="text-sm font-bold text-gray-300">{host.total_events || 0}</div>
              <div className="text-[10px] text-gray-600 mt-1">All Activity</div>
            </div>
            <div className="bg-[#121212] p-4 rounded-lg border border-gray-800">
              <div className="text-[10px] uppercase font-bold text-gray-500 mb-1">Security Events</div>
              <div className="text-sm font-bold text-red-500">{host.security_events || 0}</div>
              <div className="text-[10px] text-gray-600 mt-1">Alerts/Blocks</div>
            </div>
          </div>

          <div className="bg-[#121212] p-6 rounded-lg border border-gray-800">
            <div className="flex justify-between items-center mb-6">
                <h4 className="text-xs font-bold text-gray-400 uppercase flex items-center gap-2">
                  <BarChart2 size={16} className="text-blue-500" /> 24-Hour Anomaly Trend
                </h4>
                {realHistory.length > 0 && (
                    <span className="text-[10px] text-gray-600">Resolution: 10m intervals</span>
                )}
            </div>
            <div className="h-48">
              {realHistory.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart 
                        data={realHistory}
                        onMouseMove={(e) => {
                            if (e && e.activePayload) {
                                setHoveredPoint(e.activePayload[0].payload);
                            }
                        }}
                        onMouseLeave={() => setHoveredPoint(null)}
                    >
                    <defs>
                        <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={getAnomalyColor(host.score)} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={getAnomalyColor(host.score)} stopOpacity={0}/>
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                    <XAxis dataKey="time" hide />
                    <YAxis hide domain={[0, 10]} />
                    <Tooltip 
                        contentStyle={{ backgroundColor: '#000', border: '1px solid #333', color: '#fff' }}
                        itemStyle={{ color: getAnomalyColor(host.score) }}
                    />
                    <Area type="monotone" dataKey="score" stroke={getAnomalyColor(host.score)} fillOpacity={1} fill="url(#colorScore)" strokeWidth={2}/>
                    </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-gray-600 italic">
                    <Activity size={32} className="mb-2 opacity-20" />
                    <span className="text-xs text-center px-10">Collecting historical data points...<br/>Graph will populate as history is recorded.</span>
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-[#121212] p-5 rounded-lg border border-gray-800">
              <h4 className="text-xs font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                <Zap size={16} className="text-yellow-500" /> Bandwidth Consumption
              </h4>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-500 flex items-center gap-1"><ArrowUpRight size={12} className="text-green-500" /> Upload</span>
                    <span className="text-white font-mono">{formatBytes(stats.bandwidth.up)}</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-900 rounded-full overflow-hidden">
                    <div className="h-full bg-green-500 rounded-full" style={{ width: stats.bandwidth.up > 0 ? '65%' : '0%' }}></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-500 flex items-center gap-1"><ArrowDownLeft size={12} className="text-blue-500" /> Download</span>
                    <span className="text-white font-mono">{formatBytes(stats.bandwidth.down)}</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-900 rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 rounded-full" style={{ width: stats.bandwidth.down > 0 ? '45%' : '0%' }}></div>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-[#121212] p-5 rounded-lg border border-gray-800">
              <h4 className="text-xs font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
                <Shield size={16} className="text-blue-500" /> Active Ports & Protocols
              </h4>
              <div className="flex flex-wrap gap-2">
                {Array.from(stats.ports).map(port => (
                  <span key={port} className="px-2 py-1 bg-black border border-gray-800 rounded text-[10px] font-mono text-blue-400">
                    {port}
                  </span>
                ))}
                {stats.ports.size === 0 && <div className="text-[10px] text-gray-600 italic">No port data available</div>}
              </div>
            </div>
          </div>

          <div className="bg-[#121212] p-6 rounded-lg border border-gray-800">
            <h4 className="text-xs font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
              <History size={16} className="text-red-500" /> Recent Anomaly Events (Forensic Log)
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-gray-800 text-[10px] text-gray-500 uppercase font-bold">
                    <th className="pb-2 font-bold">Timestamp</th>
                    <th className="pb-2 font-bold">Score</th>
                    <th className="pb-2 font-bold">Reason</th>
                    <th className="pb-2 font-bold">Context / Message</th>
                  </tr>
                </thead>
                <tbody className="text-[11px] font-mono">
                  {anomalyLogs.length > 0 ? anomalyLogs.map((log, i) => (
                    <tr key={i} className="border-b border-gray-800/50 hover:bg-white/5 transition-colors">
                      <td className="py-2 text-gray-400">{log.time}</td>
                      <td className="py-2 font-black" style={{ color: getAnomalyColor(log.score) }}>{log.score.toFixed(2)}</td>
                      <td className="py-2 text-gray-200">{log.reason}</td>
                      <td className="py-2 text-gray-500 truncate max-w-[200px]" title={log.msg}>{log.msg}</td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="4" className="py-8 text-center text-gray-600 italic uppercase tracking-widest text-[9px]">
                        No persistent anomaly spikes recorded for this asset.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-[#121212] p-5 rounded-lg border border-gray-800">
            <div className="flex justify-between items-center mb-4">
                <h4 className="text-xs font-bold text-gray-400 uppercase flex items-center gap-2">
                  <Activity size={16} className="text-purple-500" /> Peer Connections ({stats.connections.length})
                </h4>
                {stats.connections.length > 0 && (
                    <button 
                        onClick={handleExportConnections}
                        className="p-1.5 hover:bg-white/10 rounded transition-colors text-gray-500 hover:text-blue-400"
                        title="Export Connections CSV"
                    >
                        <Download size={14} />
                    </button>
                )}
            </div>
            <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar">
              {stats.connections.map(peer => (
                <div key={peer.id} className="flex justify-between items-center p-2 rounded bg-black/30 border border-gray-800 hover:border-gray-700 transition-all group cursor-pointer" onClick={() => onClose() || onHostClick(peer.id)}>
                  <div className="flex items-center gap-2">
                    <div className="p-1 bg-gray-800 rounded">
                      <Server size={12} className="text-gray-400" />
                    </div>
                    <span className="text-xs font-mono text-gray-300">{peer.id}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <PeerSourceBadges sources={peer.sources} />
                    <ChevronRight size={14} className="text-gray-700 group-hover:text-blue-500 transition-colors" />
                  </div>
                </div>
              ))}
              {stats.connections.length === 0 && <div className="text-center py-4 text-gray-600 text-xs italic">No peer connections found</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};


const DigitalClock = () => {
  const [date, setDate] = useState(new Date());
  useEffect(() => { const timer = setInterval(() => setDate(new Date()), 1000); return () => clearInterval(timer); }, []);
  const formatTime = (d, timeZone) => { try { return d.toLocaleTimeString('en-US', { timeZone: timeZone, hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch (e) { return "--:--:--" } };
  const utcTime = formatTime(date, 'UTC');
  const localTime = date.toLocaleTimeString('en-US', { hour12: false });
  const localZoneCode = date.toLocaleTimeString('en-us',{timeZoneName:'short'}).split(' ').pop();
  return (
    <div className="flex flex-col items-end justify-center">
      <div className="flex items-center gap-2 text-blue-400"><span className="text-[10px] font-bold tracking-widest opacity-60">UTC</span><span className="font-mono text-xl tracking-widest leading-none" style={{ fontFamily: '"Courier New", Courier, monospace', textShadow: '0 0 10px rgba(59, 130, 246, 0.5)' }}>{utcTime}</span></div>
      <div className="flex items-center gap-2 text-green-500 mt-1"><span className="text-[10px] font-bold tracking-widest opacity-60">{localZoneCode}</span><span className="font-mono text-sm tracking-widest leading-none" style={{ fontFamily: '"Courier New", Courier, monospace', textShadow: '0 0 5px rgba(0, 208, 101, 0.5)' }}>{localTime}</span></div>
    </div>
  );
};

const AnomalyLegend = () => (
    <div className="bg-[#121212] border border-gray-800 rounded-lg p-4 shadow-lg">
        <h3 className="text-gray-300 text-sm font-bold mb-3 uppercase">Legend</h3>
        <div className="flex items-center justify-start gap-4 text-xs text-gray-400">
            <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: THEME.green }}></div>
                <span>Normal (0-2)</span>
            </div>
            <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: THEME.orange }}></div>
                <span>Elevated (3-5)</span>
            </div>
            <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: THEME.red }}></div>
                <span>High (&gt;5)</span>
            </div>
        </div>
    </div>
);

// UPDATE EVENT STREAM TO SHOW ANOMALY SCORE
const EventStream = ({ logs, defaultSearch = '', onHostClick }) => {
  const [filterText, setFilterText] = useState(defaultSearch);
  const [filterCat, setFilterCat] = useState('all');
  const [filterPrio, setFilterPrio] = useState('all');
  const [filterSec, setFilterSec] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isPaused, setIsPaused] = useState(false);
  const [displayLogs, setDisplayLogs] = useState([]);

  useEffect(() => { if (defaultSearch !== undefined) { setFilterText(defaultSearch); } }, [defaultSearch]);
  useEffect(() => { if (!isPaused) setDisplayLogs(logs); }, [logs, isPaused]);

  const filteredLogs = displayLogs.filter(log => {
    const matchesText = (log.host || '').toLowerCase().includes(filterText.toLowerCase()) || (log.msg || '').toLowerCase().includes(filterText.toLowerCase());
    const matchesCat = filterCat === 'all' || log.category === filterCat;
    const matchesPrio = filterPrio === 'all' || (log.priority || 'low') === filterPrio;
    const matchesSec = filterSec === 'all' || (filterSec === 'true' ? log.is_sec : !log.is_sec);
    return matchesText && matchesCat && matchesPrio && matchesSec;
  });

  const categories = [...new Set(logs.map(l => l.category))];

  return (
    <div className="flex flex-col h-[500px]">
       <div className="flex flex-wrap items-center gap-4 mb-4 p-2 bg-[#0a0a0a] rounded border border-gray-800">
         <div className="flex items-center gap-2 text-gray-400"><Filter size={16} /> <span className="text-xs font-bold uppercase">Filters</span></div>
         <div className="relative flex-1 min-w-[200px]"><Search className="absolute left-2 top-2 text-gray-600" size={14} /><input type="text" placeholder="Search host or message..." className="w-full bg-[#151515] border border-gray-700 rounded pl-8 pr-2 py-1 text-xs text-white focus:border-green-500 focus:outline-none" value={filterText} onChange={(e) => setFilterText(e.target.value)} /></div>
         <select className="bg-[#151515] border border-gray-700 rounded py-1 px-2 text-xs text-gray-300 focus:border-green-500 focus:outline-none" value={filterCat} onChange={(e) => setFilterCat(e.target.value)}><option value="all">All Categories</option>{categories.map((c, i) => <option key={i} value={c}>{c}</option>)}</select>
         <select className="bg-[#151515] border border-gray-700 rounded py-1 px-2 text-xs text-gray-300 focus:border-green-500 focus:outline-none" value={filterPrio} onChange={(e) => setFilterPrio(e.target.value)}><option value="all">All Priorities</option><option value="critical">Critical</option><option value="high">High</option><option value="low">Low</option></select>
         <select className="bg-[#151515] border border-gray-700 rounded py-1 px-2 text-xs text-gray-300 focus:border-green-500 focus:outline-none" value={filterSec} onChange={(e) => setFilterSec(e.target.value)}><option value="all">Security: All</option><option value="true">Yes</option><option value="false">No</option></select>
         <button onClick={() => setIsPaused(!isPaused)} className={`p-1.5 rounded border flex items-center gap-2 text-xs font-bold ${isPaused ? 'border-red-500 text-red-500 bg-red-900/20' : 'border-gray-700 text-gray-400 hover:text-white'}`}>{isPaused ? <><Pause size={14} /> PAUSED</> : <><Play size={14} /> LIVE</>}</button>
       </div>
       <div className="flex-1 overflow-y-auto custom-scrollbar border border-gray-800 rounded bg-[#050505] mb-4">
          <table className="w-full text-xs font-mono text-left">
            <thead className="bg-[#111] text-gray-500 sticky top-0 z-10">
              <tr>
                  <th className="px-4 py-2">Time</th>
                  <th className="px-4 py-2">Prio</th>
                  <th className="px-4 py-2 text-center">Sec</th>
                  <th className="px-4 py-2 text-center">AI Score</th>
                  <th className="px-4 py-2">Category</th>
                  <th className="px-4 py-2">Host</th>
                  <th className="px-4 py-2">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-900">
              {filteredLogs.map((log, i) => (
                <tr key={i} className={`hover:bg-[#151515] transition-colors cursor-pointer ${selectedLog === log ? 'bg-[#1a1a1a] border-l-2 border-green-500' : ''}`} onClick={() => setSelectedLog(log)}>
                  <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{log.time}</td>
                  <td className={`px-4 py-2 font-bold uppercase ${log.priority === 'critical' || log.priority === 'high' ? 'text-red-500' : 'text-gray-500'}`}>{log.priority || '-'}</td>
                  <td className="px-4 py-2 text-center">{log.is_sec ? <ShieldAlert size={14} className="text-red-500 inline" /> : <ShieldCheck size={14} className="text-gray-600 inline" />}</td>
                  
                  {/* NEW COLUMN: AI ANOMALY SCORE */}
                  <td className={`px-4 py-2 text-center font-bold`} style={{ color: getAnomalyColor(log.anomaly_score) }}>
                      {log.anomaly_score > -1 ? log.anomaly_score.toFixed(2) : '-'}
                  </td>

                  <td className="px-4 py-2 text-blue-400 whitespace-nowrap truncate max-w-[150px]">{log.category}</td>
                  <td 
                    className="px-4 py-2 text-purple-400 whitespace-nowrap hover:text-purple-300 hover:underline"
                    onClick={(e) => {
                        if (onHostClick) {
                            e.stopPropagation();
                            onHostClick(log.host);
                        }
                    }}
                  >
                    {log.host}
                  </td>
                  <td className="px-4 py-2 text-gray-400 truncate max-w-xs">{log.msg}</td>
                </tr>
              ))}
            </tbody>
          </table>
       </div>
       {selectedLog && (
         <div className="bg-[#0a0a0a] border-t border-green-500/30 p-4 h-64 overflow-y-auto custom-scrollbar animate-in slide-in-from-bottom-2 fade-in duration-200">
            <div className="flex justify-between items-start mb-4 border-b border-gray-800 pb-2"><h4 className="text-green-500 font-bold text-sm uppercase flex items-center gap-2"><Terminal size={16}/> Event Inspector</h4><button onClick={() => setSelectedLog(null)} className="text-gray-500 hover:text-white"><X size={16}/></button></div>
            
            {/* EVENT UUID */}
            <div className="flex flex-col mb-4 p-2 bg-[#111] rounded border border-gray-800">
                 <span className="text-[10px] uppercase text-gray-500 font-bold">Event UUID</span>
                 <span className="text-xs text-green-400 font-mono select-all break-all">{selectedLog.uuid || selectedLog.id || 'N/A'}</span>
            </div>

            {/* DFP AI SCORES */}
            <div className="grid grid-cols-2 gap-4 mb-4 p-2 bg-[#111] rounded border border-gray-800">
                 <div className="flex flex-col">
                    <span className="text-[10px] uppercase text-gray-500 font-bold">Anomaly Score</span>
                    <span className={`text-xl font-mono font-black ${selectedLog.anomaly_score > 0.8 ? 'text-red-500' : 'text-white'}`}>
                        {selectedLog.anomaly_score > -1 ? selectedLog.anomaly_score.toFixed(4) : 'N/A'}
                    </span>
                 </div>
                 <div className="flex flex-col">
                    <span className="text-[10px] uppercase text-gray-500 font-bold">Reconstruction Error</span>
                    <span className="text-xl text-white font-mono">
                        {selectedLog.mean_abs_err > -1 ? selectedLog.mean_abs_err.toFixed(4) : 'N/A'}
                    </span>
                 </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mb-4">{Object.entries(selectedLog).filter(([k]) => k !== 'msg' && k !== 'uuid' && k !== 'id' && k !== 'anomaly_score' && k !== 'mean_abs_err').map(([key, val]) => ( <div key={key} className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">{key}</span><span className="text-xs text-white font-mono">{val.toString()}</span></div> ))}</div>
            <div className="mt-4"><span className="text-[10px] uppercase text-gray-500 font-bold block mb-1">Raw Message Payload</span><div className="bg-[#111] p-3 rounded border border-gray-800 font-mono text-xs text-gray-300 whitespace-pre-wrap break-words">{selectedLog.msg}</div></div>
         </div>
       )}
    </div>
  );
};

const MajorAnomalyEventTable = ({ logs = [], onHostClick }) => {
  const [filterReason, setFilterReason] = useState('all');

  const latestAnomaliesByHost = logs.reduce((acc, log) => {
    acc[log.host] = log;
    return acc;
  }, {});

  const latestAnomalies = Object.values(latestAnomaliesByHost);

  // FIX: Safe access for reasons (filter out undefined/null reasons)
  const reasons = [...new Set(latestAnomalies.map(l => l.reason).filter(Boolean))];

  const filteredLogs = latestAnomalies.filter(log => {
    return filterReason === 'all' || log.reason === filterReason;
  });

  return (
    <div className="flex flex-col h-[300px]">
      <div className="flex items-center gap-4 mb-4 p-2 bg-[#0a0a0a] rounded border border-gray-800">
        <div className="flex items-center gap-2 text-gray-400"><Filter size={16} /> <span className="text-xs font-bold uppercase">Filter by Reason</span></div>
        <select className="bg-[#151515] border border-gray-700 rounded py-1 px-2 text-xs text-gray-300 focus:border-green-500 focus:outline-none" value={filterReason} onChange={(e) => setFilterReason(e.target.value)}>
          <option value="all">All Reasons</option>
          {reasons.map((r, i) => <option key={i} value={r}>{r}</option>)}
        </select>
      </div>
      <div className="h-full overflow-y-auto custom-scrollbar">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredLogs.map((log, i) => (
            <div key={i} className="bg-[#121212] border border-gray-800 rounded-lg p-4 shadow-lg cursor-pointer" onClick={() => onHostClick(log)}>
              <div className="flex items-center mb-2">
                <Server size={16} className="text-red-500 mr-2" />
                <h4 className="text-sm font-bold text-white truncate">{log.host}</h4>
              </div>
              
              {/* --- CRASH FIX IS HERE --- */}
              <div className="text-xs text-gray-400 mb-2">
                {/* 1. Check if current_score is a number */}
                <span className="font-bold text-red-500">
                    {typeof log.current_score === 'number' ? log.current_score.toFixed(2) : '0.00'}
                </span>
                
                {/* 2. Check if previous_score is a number before calling toFixed */}
                <span className="text-gray-500"> 
                    (previously {typeof log.previous_score === 'number' ? log.previous_score.toFixed(2) : 'N/A'})
                </span>
              </div>
              {/* ------------------------- */}

              <p className="text-xs text-gray-300">{log.reason || 'Unknown Reason'}</p>
            </div>
          ))}
          {filteredLogs.length === 0 && (
            <div className="col-span-full text-center py-10 text-gray-600 italic">
              Waiting for major anomaly events...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const SudoLogTable = ({ logs, onHostClick }) => {
  const [selectedLog, setSelectedLog] = useState(null);

  return (
    <div className="flex flex-col h-[600px]">
       <div className="flex-1 overflow-y-auto custom-scrollbar border border-gray-800 rounded bg-[#050505]">
          <table className="w-full text-xs font-mono text-left">
            <thead className="bg-[#111] text-gray-500 sticky top-0 z-10">
              <tr>
                <th className="px-4 py-2">Time</th>
                <th className="px-4 py-2">Host</th>
                <th className="px-4 py-2">Executing User</th>
                <th className="px-4 py-2">Run As User</th>
                <th className="px-4 py-2">Command</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-900">
              {logs.map((log, i) => (
                <tr key={i} onClick={() => setSelectedLog(log)} className={`hover:bg-[#151515] transition-colors cursor-pointer group ${selectedLog === log ? 'bg-[#1a1a1a] border-l-2 border-blue-500' : ''}`}>
                  <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{log.time}</td>
                  <td 
                    className="px-4 py-2 text-purple-400 whitespace-nowrap hover:text-purple-300 hover:underline"
                    onClick={(e) => {
                        if (onHostClick) {
                            e.stopPropagation();
                            onHostClick(log.host);
                        }
                    }}
                  >
                    {log.host}
                  </td>
                  <td className="px-4 py-2 text-green-400">{log.executing_user}</td>
                  <td className="px-4 py-2 text-orange-400">{log.run_as_user}</td>
                  <td className="px-4 py-2 text-gray-300 truncate max-w-xs">{log.command}</td>
                </tr>
              ))}
              {logs.length === 0 && ( <tr><td colSpan={5} className="text-center py-10 text-gray-600 italic">Waiting for sudo events...</td></tr> )}
            </tbody>
          </table>
       </div>
       {selectedLog && (
         <div className="bg-[#0a0a0a] border-t border-blue-500/30 p-4 h-64 overflow-y-auto custom-scrollbar animate-in slide-in-from-bottom-2 fade-in duration-200">
            <div className="flex justify-between items-start mb-4 border-b border-gray-800 pb-2">
               <h4 className="text-blue-500 font-bold text-sm uppercase flex items-center gap-2"><Terminal size={16}/> Sudo Command Details</h4>
               <button onClick={() => setSelectedLog(null)} className="text-gray-500 hover:text-white"><X size={16}/></button>
            </div>
            <div className="grid grid-cols-4 gap-4 mb-4">
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Time</span><span className="text-xs text-white font-mono">{selectedLog.time}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Host</span><span className="text-xs text-white font-mono">{selectedLog.host}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Executing User</span><span className="text-xs text-white font-mono">{selectedLog.executing_user}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Run As User</span><span className="text-xs text-white font-mono">{selectedLog.run_as_user}</span></div>
            </div>
            <div className="mt-4"><span className="text-[10px] uppercase text-gray-500 font-bold block mb-1">Full Command</span><div className="bg-[#111] p-3 rounded border border-gray-800 font-mono text-xs text-gray-300 whitespace-pre-wrap break-words">{selectedLog.command}</div></div>
         </div>
       )}
    </div>
  );
};

const NetworkLogTable = ({ logs, onHostClick }) => {
  const [selectedLog, setSelectedLog] = useState(null);
  const [filters, setFilters] = useState({ srcIp: '', srcPort: '', dstIp: '', dstPort: '' });
   
  const blockLogs = logs.filter(l => {
    if (l.category === 'Firewall' || l.category === 'firewall_block') return true;
    const text = (l.msg || l.message || '').toLowerCase();
    return text.includes('block') || text.includes('deny') || text.includes('drop') || text.includes('allow') || 
           text.includes('%ftd') || text.includes('%asa') || text.includes('%fpfw');
  });

  const parsedLogs = blockLogs.map(log => {
      const rawText = log.msg || log.message || '';
      const parsed = parseFirewallData(rawText);
      return { ...log, ...parsed };
  });

  const filteredLogs = parsedLogs.filter(log => {
    const hasIps = log.srcIp && log.srcIp !== '-' && log.dstIp && log.dstIp !== '-';
    if (!hasIps) return false;
    const matchSrc = filters.srcIp === '' || log.srcIp.includes(filters.srcIp);
    const matchSPort = filters.srcPort === '' || log.srcPort.includes(filters.srcPort);
    const matchDst = filters.dstIp === '' || log.dstIp.includes(filters.dstIp);
    const matchDPort = filters.dstPort === '' || log.dstPort.includes(filters.dstPort);
    return matchSrc && matchSPort && matchDst && matchDPort;
  });

  return (
    <div className="flex flex-col h-[600px]">
       <div className="flex flex-wrap items-center gap-2 mb-4 p-2 bg-[#0a0a0a] rounded border border-gray-800">
         <div className="flex items-center gap-2 text-gray-400 mr-2"><Filter size={16} /> <span className="text-xs font-bold uppercase">Block Filter</span></div>
         <input type="text" placeholder="Src IP" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-32 focus:border-red-500 focus:outline-none" value={filters.srcIp} onChange={(e) => setFilters({...filters, srcIp: e.target.value})} />
         <input type="text" placeholder="S.Port" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-20 focus:border-red-500 focus:outline-none" value={filters.srcPort} onChange={(e) => setFilters({...filters, srcPort: e.target.value})} />
         <ArrowRight size={14} className="text-gray-600" />
         <input type="text" placeholder="Dst IP" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-32 focus:border-red-500 focus:outline-none" value={filters.dstIp} onChange={(e) => setFilters({...filters, dstIp: e.target.value})} />
         <input type="text" placeholder="D.Port" className="bg-[#151515] border border-gray-700 rounded px-2 py-1 text-xs text-white w-20 focus:border-red-500 focus:outline-none" value={filters.dstPort} onChange={(e) => setFilters({...filters, dstPort: e.target.value})} />
         <div className="ml-auto text-xs text-red-400 font-mono font-bold">{filteredLogs.length} EVENTS</div>
       </div>
       <div className="flex-1 overflow-y-auto custom-scrollbar border border-gray-800 rounded bg-[#050505]">
          <table className="w-full text-xs font-mono text-left">
            <thead className="bg-[#111] text-gray-500 sticky top-0 z-10">
              <tr>
                <th className="px-4 py-2">Time</th><th className="px-4 py-2">Action</th><th className="px-4 py-2">Source</th><th className="px-4 py-2">Destination</th><th className="px-4 py-2">Proto</th><th className="px-4 py-2">Location</th><th className="px-4 py-2">ASN</th><th className="px-4 py-2">Policy</th><th className="px-4 py-2">Rule</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-900">
              {filteredLogs.map((log, i) => (
                <tr key={i} onClick={() => setSelectedLog(log)} className={`hover:bg-[#151515] transition-colors cursor-pointer group ${selectedLog === log ? 'bg-[#1a1a1a] border-l-2 border-red-500' : ''}`}>
                  <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{log.time}</td>
                  <td className={`px-4 py-2 font-bold uppercase ${log.action.toLowerCase() === 'allow' ? 'text-green-500' : 'text-red-500'}`}>{log.action}</td>
                  <td 
                    className="px-4 py-2 text-gray-300 hover:text-white hover:underline"
                    onClick={(e) => { if (onHostClick && log.srcIp !== '-') { e.stopPropagation(); onHostClick(log.srcIp); } }}
                  >
                    {log.srcIp} <span className="text-gray-600">:{log.srcPort}</span>
                  </td>
                  <td 
                    className="px-4 py-2 text-gray-300 hover:text-white hover:underline"
                    onClick={(e) => { if (onHostClick && log.dstIp !== '-') { e.stopPropagation(); onHostClick(log.dstIp); } }}
                  >
                    {log.dstIp} <span className="text-gray-600">:{log.dstPort}</span>
                  </td>
                  <td className="px-4 py-2 text-blue-400">{log.proto}</td>
                  <td className="px-4 py-2 text-gray-400">{log.city || '-'}</td>
                  <td className="px-4 py-2 text-gray-400 truncate max-w-[100px]" title={log.org}>{log.asn ? `AS${log.asn}` : '-'}</td>
                  <td className="px-4 py-2 text-gray-400">{log.acPolicy}</td>
                  <td className="px-4 py-2 text-gray-400 truncate max-w-[150px]" title={log.ruleName}>{log.ruleName}</td>
                </tr>
              ))}
              {filteredLogs.length === 0 && ( <tr><td colSpan={7} className="text-center py-10 text-gray-600 italic">Waiting for firewall events...</td></tr> )}
            </tbody>
          </table>
       </div>
       {selectedLog && (
         <div className="bg-[#0a0a0a] border-t border-red-500/30 p-4 h-64 overflow-y-auto custom-scrollbar animate-in slide-in-from-bottom-2 fade-in duration-200">
            <div className="flex justify-between items-start mb-4 border-b border-gray-800 pb-2">
               <h4 className="text-red-500 font-bold text-sm uppercase flex items-center gap-2"><FileText size={16}/> Packet Inspector</h4>
               <button onClick={() => setSelectedLog(null)} className="text-gray-500 hover:text-white"><X size={16}/></button>
            </div>
            {/* --- EVENT UUID --- */}
            <div className="mb-4 p-2 bg-[#111] rounded border border-gray-800">
                 <span className="text-[10px] uppercase text-gray-500 font-bold block mb-1">Packet UUID</span>
                 <span className="text-xs text-gray-300 font-mono select-all break-all">{selectedLog.uuid || selectedLog.id || 'N/A'}</span>
            </div>
            <div className="grid grid-cols-4 gap-4 mb-4">
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Source</span><span className="text-xs text-white font-mono">{selectedLog.srcIp}:{selectedLog.srcPort}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Destination</span><span className="text-xs text-white font-mono">{selectedLog.dstIp}:{selectedLog.dstPort}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Protocol</span><span className="text-xs text-blue-400 font-mono">{selectedLog.proto}</span></div>
               <div className="flex flex-col"><span className="text-[10px] uppercase text-gray-500 font-bold">Action</span><span className={`text-xs font-bold font-mono ${selectedLog.action.toLowerCase() === 'allow' ? 'text-green-500' : 'text-red-500'}`}>{selectedLog.action}</span></div>
            </div>
            <div className="mt-4"><span className="text-[10px] uppercase text-gray-500 font-bold block mb-1">Raw Payload</span><div className="bg-[#111] p-3 rounded border border-gray-800 font-mono text-xs text-gray-300 whitespace-pre-wrap break-words">{selectedLog.msg || selectedLog.message}</div></div>
         </div>
       )}
    </div>
  );
};

export default App;
