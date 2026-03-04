import React from 'react';
import { Activity } from 'lucide-react'; // Example icon
// Import a small line chart for the trend line if you have the data

const GTT_GREEN = "#00D065";

function Header() {
  const threatLevel = 10.0; // Replace with real data
  const threatLabel = "CRITICAL";

  return (
    <header className="flex justify-between items-start mb-8">
      {/* Left: Title & Branding */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          GTT <span style={{ color: GTT_GREEN }}>CYBER INTELLIGENCE</span>
        </h1>
        <p className="text-gray-400 text-sm mt-1 flex items-center">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
          Real-Time Network & Host Forensics
        </p>
      </div>

      {/* Right: Threat Level Metric */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col items-end">
        <div className="text-xs text-gray-500 uppercase font-bold mb-1">Threat Level ({threatLabel})</div>
        <div className="text-4xl font-bold text-red-500 flex items-center">
          <Activity className="mr-2 h-8 w-8" /> {/* Replace with your shield icon */}
          {threatLevel.toFixed(1)}
        </div>
        <div className="text-xs text-gray-400 mt-1">↑ 1-10 Scale</div>
        {/* Insert small Recharts Sparkline here for the trend */}
        <div className="h-8 w-32 bg-red-900/20 mt-2 rounded"></div>
      </div>
    </header>
  );
}

export default Header;
