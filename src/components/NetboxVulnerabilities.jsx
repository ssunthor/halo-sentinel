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
                if (data.length > 0) {
                    setSelectedRole(data[0]);
                }
            } catch (e) {
                setError(e.message);
            }
        };

        fetchRoles();
    }, [backendReady, apiBase]);

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
        <div className="p-4 bg-black text-white">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-2xl font-bold">Netbox Device Vulnerabilities</h2>
                <div className="flex items-center">
                    <label htmlFor="role-select" className="mr-2 text-gray-400">Select Role:</label>
                    <select
                        id="role-select"
                        value={selectedRole}
                        onChange={(e) => setSelectedRole(e.target.value)}
                        className="bg-gray-800 border border-gray-700 rounded-md p-2 text-white"
                    >
                        {roles.map(role => (
                            <option key={role} value={role}>{role}</option>
                        ))}
                    </select>
                </div>
            </div>
            
            {loading ? (
                <div className="text-white">Loading Netbox vulnerabilities for {selectedRole}...</div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4">
                    {devices.map((device, index) => (
                            <div 
                            key={device.device_name} 
                            className={`p-2 rounded-lg border-2 cursor-pointer transition-all duration-300 flex flex-col items-center justify-center ${severityColors[getSeverityColor(device.highest_severity_score)]}`}
                            onClick={() => setSelectedDevice(device)}
                        >
                            <div className="flex items-center mb-1">
                                <Server size={16} className="mr-2" />
                                <h3 className="text-md font-bold text-green-500 truncate" title={device.device_name.toUpperCase()}>
                                    {device.device_name.length > 18 ? `${device.device_name.substring(0, 18).toUpperCase()}...` : device.device_name.toUpperCase()}
                                </h3>
                            </div>
                            <p className="text-xs text-gray-400">{device.device_type}</p>
                            <p className="text-xs mt-1">
                                CVE: 
                                <span className={`font-bold ${getSeverityTextClass(device.highest_severity_score)} ml-1`}>
                                    {device.highest_severity_score && device.highest_severity_score > 0 ? device.highest_severity_score : "Unknown"}
                                </span>
                            </p>
                        </div>
                    ))}
                </div>
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
