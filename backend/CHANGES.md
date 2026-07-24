# Changes - May 28, 2026

## Netbox CVE Scanner Refactoring

- **Removed "Roles" Logic**: Completely removed the concept of device roles from both backend and frontend. The scanner now performs global or tenant-wide scans.
- **Simplified Data Structure**: Migrated `vulnerable_devices_cache` from a role-keyed dictionary to a unified flat list.
- **API Updates**:
  - Deleted the `/netbox/roles` endpoint.
  - Updated `/netbox/vulnerabilities` and `/netbox/virtual-machines` to return all resources from the flat cache.
  - Updated frontend components to remove role-selection UI elements.

## Performance & UX Optimizations

- **Streaming Updates**: Redesigned the scan process to be non-blocking. Results now stream into the UI as they are found rather than waiting for the entire fleet to be pre-fetched from NVD.
- **Non-Blocking LLM Integration**: Moved all LLM calls (Analysis, Summarization, Chat) to a background thread pool (`run_in_executor`) to prevent blocking the main FastAPI event loop.
- **In-Flight Request Deduplication**: The vulnerability broker now tracks active NVD requests, ensuring multiple devices with the same OS only trigger a single shared API call.
- **Concurrency Limiting**: Implemented an `asyncio.Semaphore` (limit: 20) to stabilize processing and prevent overwhelming external LLM and NVD APIs.
- **Real-Time Progress**: Backend now performs incremental cache updates (after CVE discovery and again after AI analysis) so the progress bar reflects actual work completed.

## Persistence & Caching

- **Persistent Local Cache**: Implemented disk-backed storage for NVD CVE data and LLM analysis results. Caches are loaded on startup and saved incrementally.
- **Query Normalization**: Added strict normalization for software signatures to maximize cache hit rates and reduce NVD API usage.

## Bug Fixes

- Fixed a `NameError` caused by the initialization order of cache loading functions.
- Resolved an issue where the frontend page would go blank during high-concurrency scans.
- Fixed a stagnant 0% progress bar by ensuring the scanner reports status changes before long-running AI tasks.
