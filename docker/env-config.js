// Single-container build: the SPA and the API share one origin (nginx proxies
// /api -> the in-container backend), so the API base is empty = same-origin.
// The frontend resolvers use `??`, so this empty string is respected.
window._env_ = { VITE_API_BASE_URL: "" };
