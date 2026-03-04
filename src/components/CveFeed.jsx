import React, { useState, useEffect } from 'react';
import { ShieldAlert } from 'lucide-react';

const CveFeed = () => {
  const [cves, setCves] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchCves = async () => {
      setLoading(true);
      setError(null);
      try {
        const apiBase = window._env_?.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE_URL || 'http://10.250.133.153:15174';
        const proxyUrl = `${apiBase}/cve-proxy`;
        const response = await fetch(proxyUrl);
        if (!response.ok) {
          throw new Error(`Failed to fetch CVEs: ${response.statusText}`);
        }
        const data = await response.json();
        setCves(data.vulnerabilities || []);
      } catch (err) {
        setError(err.message);
      }
      setLoading(false);
    };

    fetchCves();
  }, []);

  if (error) {
    return (
      <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
        <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
          <ShieldAlert size={16} /> Latest CVEs
        </h3>
        <p className="text-red-500">{error}</p>
      </div>
    );
  }

  return (
    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
      <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
        <ShieldAlert size={16} /> Latest CVEs
      </h3>
      <div className="h-64 overflow-y-auto custom-scrollbar">
        {loading ? (
          <p>Loading CVEs...</p>
        ) : (
          <ul>
            {cves.map(({ cve }) => (
              <li key={cve.id} className="mb-2">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-green-500 hover:text-green-400 transition-colors"
                >
                  {cve.id}
                </a>
                <p className="text-xs text-gray-400">{cve.descriptions[0].value}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default CveFeed;
