import React, { useState, useEffect } from 'react';
import { Server, X } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const getSeverityColor = (score) => {
    if (!score || score === 0) return 'green';
    if (score >= 7) return 'red';
    if (score >= 4) return 'orange';
    return 'yellow';
};

const getSeverityTextClass = (score) => {
    if (!score || score === 0) return 'text-green-500';
    if (score >= 7) return 'text-red-500';
    if (score >= 4) return 'text-orange-500';
    return 'text-yellow-500';
};

const NetboxVulnerabilities = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedDevice, setSelectedDevice] = useState(null);
    const [overallSummary, setOverallSummary] = useState("");
    const [roles, setRoles] = useState([]);
    const [selectedRole, setSelectedRole] = useState('');
    const [backendReady, setBackendReady] = useState(false);

    // Pagination and Search State
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(25);

    const apiBase = window._env_?.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE_URL || 'http://10.250.133.153:15174';

    useEffect(() => {
        const checkBackendStatus = async () => {
            try {
                const response = await fetch(`${apiBase}/status`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                if (data.initial_scan_complete) {
                    setBackendReady(true);
                }
            } catch (e) {
                console.error("Error checking backend status:", e);
            }
        };

        const interval = setInterval(() => {
            if (!backendReady) {
                checkBackendStatus();
            }
        }, 2000);

        return () => clearInterval(interval);
    }, [backendReady, apiBase]);

    useEffect(() => {
        const fetchRoles = async () => {
            if (!backendReady) return;
            try {
                const response = await fetch(`${apiBase}/netbox/roles`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                setRoles(data);
                if (data.length > 0 && !selectedRole) {
                    setSelectedRole(data[0]);
                }
            } catch (e) {
                setError(e.message);
            }
        };

        fetchRoles();
    }, [backendReady, apiBase, selectedRole]);

    useEffect(() => {
        const fetchVulnerabilities = async (role) => {
            if (!role || !backendReady) return;
            setLoading(true);
            try {
                const response = await fetch(`${apiBase}/netbox/vulnerabilities?role=${role}`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                setDevices(data);
                setCurrentPage(1); // Reset to page 1 on role change
            } catch (e) {
                setError(e.message);
            } finally {
                setLoading(false);
            }
        };

        fetchVulnerabilities(selectedRole);
    }, [selectedRole, backendReady, apiBase]);

    useEffect(() => {
        const fetchOverallSummary = async () => {
            if (!backendReady) return;
            try {
                const response = await fetch(`${apiBase}/netbox/overall-summary`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                setOverallSummary(data);
            } catch (e) {
                console.error("Error fetching overall summary:", e);
            }
        };

        fetchOverallSummary();
    }, [backendReady, apiBase]);

    // Filtering Logic
    const filteredDevices = devices.filter(device => {
        const search = searchTerm.toLowerCase();
        return (
            device.device_name?.toLowerCase().includes(search) ||
            device.device_type?.toLowerCase().includes(search) ||
            device.os?.toLowerCase().includes(search)
        );
    });

    // Pagination Logic
    const effectiveItemsPerPage = itemsPerPage === 'All' ? filteredDevices.length : parseInt(itemsPerPage);
    const totalPages = Math.ceil(filteredDevices.length / (effectiveItemsPerPage || 1));
    const indexOfLastItem = currentPage * (effectiveItemsPerPage || filteredDevices.length);
    const indexOfFirstItem = indexOfLastItem - (effectiveItemsPerPage || filteredDevices.length);
    const currentItems = filteredDevices.slice(indexOfFirstItem, indexOfLastItem);

    if (!backendReady) {
        return <div className="text-white">Waiting for backend to be ready...</div>;
    }
    
    if (error) {
        return <div className="text-red-500">Error fetching data: {error}</div>;
    }

    const severityColors = {
        red: 'border-red-500 bg-red-900/20',
        orange: 'border-orange-500 bg-orange-900/20',
        yellow: 'border-yellow-500 bg-yellow-900/20',
        green: 'border-green-500 bg-green-900/20',
    };

    return (
        <div className="p-4 bg-black text-white min-h-screen">
            {/* Header and Filters */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 bg-gray-900/50 p-4 rounded-xl border border-gray-800">
                <div>
                    <h2 className="text-2xl font-bold text-green-500">Netbox Vulnerabilities</h2>
                    <p className="text-xs text-gray-500">Showing {filteredDevices.length} of {devices.length} devices</p>
                </div>
                
                <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
                    {/* Search Bar */}
                    <div className="relative flex-grow md:flex-grow-0">
                        <input
                            type="text"
                            placeholder="Search name, model, os..."
                            value={searchTerm}
                            onChange={(e) => {
                                setSearchTerm(e.target.value);
                                setCurrentPage(1);
                            }}
                            className="bg-gray-800 border border-gray-700 rounded-lg py-2 px-4 text-sm w-full md:w-64 focus:outline-none focus:ring-2 focus:ring-green-500/50"
                        />
                        {searchTerm && (
                            <button 
                                onClick={() => setSearchTerm('')}
                                className="absolute right-2 top-2 text-gray-500 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        )}
                    </div>

                    {/* Role Select */}
                    <div className="flex items-center">
                        <label className="mr-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">Role:</label>
                        <select
                            value={selectedRole}
                            onChange={(e) => setSelectedRole(e.target.value)}
                            className="bg-gray-800 border border-gray-700 rounded-lg p-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-green-500/50"
                        >
                            {roles.map(role => (
                                <option key={role} value={role}>{role}</option>
                            ))}
                        </select>
                    </div>

                    {/* Items Per Page */}
                    <div className="flex items-center">
                        <label className="mr-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">Show:</label>
                        <select
                            value={itemsPerPage}
                            onChange={(e) => {
                                setItemsPerPage(e.target.value);
                                setCurrentPage(1);
                            }}
                            className="bg-gray-800 border border-gray-700 rounded-lg p-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-green-500/50"
                        >
                            {[5, 10, 25, 100, 'All'].map(val => (
                                <option key={val} value={val}>{val}</option>
                            ))}
                        </select>
                    </div>
                </div>
            </div>
            
            {loading ? (
                <div className="flex items-center justify-center h-64">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-500"></div>
                    <span className="ml-3 text-gray-400">Scanning {selectedRole}...</span>
                </div>
            ) : (
                <>
                    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 2xl:grid-cols-6 gap-4 mb-6">
                        {currentItems.map((device) => (
                            <div 
                                key={device.device_name} 
                                className={`p-4 rounded-xl border-2 cursor-pointer transition-all duration-300 hover:scale-[1.02] flex flex-col ${severityColors[getSeverityColor(device.highest_severity_score)]}`}
                                onClick={() => setSelectedDevice(device)}
                            >
                                <div className="flex items-start justify-between mb-2">
                                    <Server size={20} className="text-gray-400 shrink-0 mt-1" />
                                    <div className="text-right">
                                        <span className={`text-lg font-black ${getSeverityTextClass(device.highest_severity_score)}`}>
                                            {device.highest_severity_score > 0 ? device.highest_severity_score.toFixed(1) : "0.0"}
                                        </span>
                                    </div>
                                </div>
                                <h3 className="text-sm font-bold text-white truncate w-full mb-1" title={device.device_name.toUpperCase()}>
                                    {device.device_name.toUpperCase()}
                                </h3>
                                <div className="mt-auto">
                                    <p className="text-[10px] text-gray-500 uppercase font-bold truncate">{device.device_type}</p>
                                    <p className="text-[10px] text-green-500/70 truncate">{device.os}</p>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Pagination Controls */}
                    {itemsPerPage !== 'All' && totalPages > 1 && (
                        <div className="flex justify-center items-center gap-2 mt-8 pb-8">
                            <button
                                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                                disabled={currentPage === 1}
                                className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 disabled:opacity-30 hover:bg-gray-700 transition-colors"
                            >
                                Previous
                            </button>
                            <div className="flex gap-1">
                                {[...Array(totalPages)].map((_, i) => {
                                    const pageNum = i + 1;
                                    // Show first, last, and pages around current
                                    if (
                                        pageNum === 1 || 
                                        pageNum === totalPages || 
                                        (pageNum >= currentPage - 1 && pageNum <= currentPage + 1)
                                    ) {
                                        return (
                                            <button
                                                key={pageNum}
                                                onClick={() => setCurrentPage(pageNum)}
                                                className={`w-10 h-10 rounded-lg border ${currentPage === pageNum ? 'bg-green-600 border-green-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'}`}
                                            >
                                                {pageNum}
                                            </button>
                                        );
                                    } else if (pageNum === currentPage - 2 || pageNum === currentPage + 2) {
                                        return <span key={pageNum} className="px-1">...</span>;
                                    }
                                    return null;
                                })}
                            </div>
                            <button
                                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                                disabled={currentPage === totalPages}
                                className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 disabled:opacity-30 hover:bg-gray-700 transition-colors"
                            >
                                Next
                            </button>
                        </div>
                    )}
                </>
            )}

            {selectedDevice && (
                <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
                    <div className="bg-gray-900 p-6 rounded-lg max-w-3xl w-full border-2 border-gray-700">
                        <div className="flex justify-between items-center mb-4">
                            <h2 className="text-2xl font-bold text-green-500">{selectedDevice.device_name.toUpperCase()}</h2>
                            <button onClick={() => setSelectedDevice(null)}>
                                <X className="text-gray-400" />
                            </button>
                        </div>
                        <div className="space-y-4 max-h-96 overflow-y-auto">
                            {selectedDevice.cves.length > 0 ? (
                                selectedDevice.cves.map((cve, index) => (
                                    <div key={index} className="p-4 bg-gray-800 rounded-lg">
                                        <div className="flex justify-between items-center">
                                            <a 
                                                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                className="text-blue-500 hover:underline font-bold"
                                            >
                                                {cve.id}
                                            </a>
                                            <span className={`font-bold ${getSeverityTextClass(cve.score)}`}>
                                                {cve.severity} - {cve.score}
                                            </span>
                                        </div>
                                        <p className="mt-2 text-gray-300">{cve.description}</p>
                                    </div>
                                ))
                            ) : (
                                <p className="text-gray-400">No vulnerabilities found for this device.</p>
                            )}
                            <div className="p-4 bg-gray-800 rounded-lg">
                                <h3 className="text-lg font-bold mb-2 text-yellow-500">AI Analysis</h3>
                                <ReactMarkdown remarkPlugins={[remarkGfm]} className="prose prose-invert">
                                    {selectedDevice.llm_analysis ? selectedDevice.llm_analysis.replace(/\n/g, '  \n') : "No AI analysis available for this device."}
                                </ReactMarkdown>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default NetboxVulnerabilities;
