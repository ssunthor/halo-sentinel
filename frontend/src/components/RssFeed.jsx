import React, { useState, useEffect } from 'react';
import { Rss, X } from 'lucide-react';

const RssFeed = ({ feeds, onRemoveFeed }) => {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchFeeds = async () => {
      setLoading(true);
      setError(null);
      const allItems = [];

      for (const feed of feeds) {
        try {
          const apiBase = window._env_?.VITE_API_BASE_URL ?? import.meta.env.VITE_API_BASE_URL ?? 'http://10.250.133.153:15174';
          const proxyUrl = `${apiBase}/rss-proxy?url=${encodeURIComponent(feed.url)}`;
          const response = await fetch(proxyUrl);
          if (!response.ok) {
            throw new Error(`Failed to fetch ${feed.url}: ${response.statusText}`);
          }
          const feedText = await response.text();
          
          const parser = new DOMParser();
          const xmlDoc = parser.parseFromString(feedText, "text/xml");
          const feedItems = Array.from(xmlDoc.querySelectorAll("item, entry")).map(item => {
            const title = item.querySelector("title")?.textContent || "";
            const link = item.querySelector("link")?.textContent || "";
            const pubDate = item.querySelector("pubDate, published")?.textContent || "";
            return {
              title,
              link,
              isoDate: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
              feedName: feed.name,
            };
          });
          
          allItems.push(...feedItems);
        } catch (err) {
          console.error(`Error fetching or parsing feed: ${feed.name}`, err);
        }
      }

      allItems.sort((a, b) => new Date(b.isoDate) - new Date(a.isoDate));
      setItems(allItems);
      setLoading(false);
    };

    if (feeds && feeds.length > 0) {
      fetchFeeds();
    } else {
      setItems([]);
    }
  }, [feeds]);

  if (error) {
    return (
      <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
        <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
          <Rss size={16} /> Emerging Threats
        </h3>
        <p className="text-red-500">{error}</p>
      </div>
    );
  }

  return (
    <div className="bg-[#121212] border border-gray-800 rounded-lg p-5 shadow-lg">
      <h3 className="text-sm font-bold text-gray-400 uppercase mb-4 flex items-center gap-2">
        <Rss size={16} /> Emerging Threats
      </h3>
      <div className="flex flex-wrap gap-2 mb-4">
        {feeds.map(feed => (
          <div key={feed.url} className="flex items-center gap-2 bg-[#1a1a1a] border border-gray-700 rounded-full px-3 py-1 text-xs">
            <span>{feed.name}</span>
            <button onClick={() => onRemoveFeed(feed.url)} className="text-gray-500 hover:text-red-500">
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
      <div className="h-64 overflow-y-auto custom-scrollbar">
        {loading ? (
          <p>Loading feeds...</p>
        ) : (
          <ul>
            {items.map((item, index) => (
              <li key={index} className="mb-2">
                <a
                  href={item.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-green-500 hover:text-green-400 transition-colors"
                >
                  {item.title}
                </a>
                <p className="text-xs text-gray-500">{item.feedName}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default RssFeed;
