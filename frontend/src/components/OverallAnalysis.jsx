import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ChevronDown, ChevronRight } from 'lucide-react';

const OverallAnalysis = () => {
    const [analysis, setAnalysis] = useState("");
    const [countdown, setCountdown] = useState(300);
    // CHANGE 1: If you want it visible by default, set this to false. 
    // If you want it hidden initially, keep it true.
    const [isCollapsed, setIsCollapsed] = useState(true); 

    useEffect(() => {
        const fetchAnalysis = async () => {
            try {
                const apiBase = window._env_?.VITE_API_BASE_URL ?? import.meta.env.VITE_API_BASE_URL ?? 'http://10.250.133.153:15174';
                const response = await fetch(`${apiBase}/overall-analysis`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                
                // CHANGE 2: Inspect 'data' to find the text field. 
                // Assuming the API returns { "response": "..." } or similar.
                // If the API returns raw text, keep 'data'. If it's an object, use 'data.field_name'
                console.log("API Data received:", data); // Debugging line
                
                // Safety check: ensure we are setting a string
                const textContent = typeof data === 'object' ? (data.response || data.message || JSON.stringify(data)) : data;
                setAnalysis(textContent);
                
            } catch (e) {
                console.error("Error fetching overall analysis:", e);
                setAnalysis("Error loading analysis."); // User feedback
            }
        };

        fetchAnalysis();
        const interval = setInterval(fetchAnalysis, 300000); 

        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const timer = setInterval(() => {
            setCountdown(prevCountdown => (prevCountdown > 0 ? prevCountdown - 1 : 300));
        }, 1000);

        return () => clearInterval(timer);
    }, []);

    const formatTime = (seconds) => {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds < 10 ? '0' : ''}${remainingSeconds}`;
    };

    return (
        <div className="p-4 bg-black rounded-lg mt-4">
            <div className="flex justify-between items-center mb-2 cursor-pointer" onClick={() => setIsCollapsed(!isCollapsed)}>
                <div className="flex items-center">
                    {isCollapsed ? <ChevronRight size={20} /> : <ChevronDown size={20} />}
                    <h3 className="text-lg font-bold text-yellow-500 ml-2">Overall AI Analysis</h3>
                </div>
                <div className="text-xs text-gray-400">
                    Next summary in: {formatTime(countdown)}
                </div>
            </div>
            
            {/* CHANGE 3: Actually use the isCollapsed state to hide/show content */}
            {!isCollapsed && (
                <div className="mt-4"> {/* Added a wrapper div for spacing */}
                    <ReactMarkdown 
                        remarkPlugins={[remarkGfm]} 
                        className="prose prose-invert prose-p:text-gray-400 prose-strong:text-green-500 prose-headings:text-yellow-500 prose-a:text-blue-500 prose-p:my-4"
                    >
                        {/* CHANGE 4: Safety check. Ensure analysis exists before replacing */}
                        {analysis ? analysis.replace(/\n/g, '  \n') : "Loading analysis..."}
                    </ReactMarkdown>
                </div>
            )}
        </div>
    );
};

export default OverallAnalysis;
