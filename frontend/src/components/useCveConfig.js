import { useState, useEffect } from 'react';

// Config-aware CVE applicability for one device (Sentinel
// GET /api/device/{name}/cve-config): config metadata + per-CVE verdicts.
// Returns null until loaded, and for the previous device while switching.
export function useCveConfig(deviceName, apiBase) {
  const [state, setState] = useState({ name: null, data: null });
  useEffect(() => {
    if (!deviceName) return undefined;
    let cancelled = false;
    fetch(`${apiBase}/api/device/${encodeURIComponent(deviceName)}/cve-config`)
      .then(r => (r.ok ? r.json() : null))
      .then(data => { if (!cancelled) setState({ name: deviceName, data }); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [deviceName, apiBase]);
  return state.name === deviceName ? state.data : null;
}
