"""
SQLite persistence layer for the CVE Analyzer.
Single WAL-mode database at /app/cache/cve_analyzer.db.
All writes are serialised through _write_lock; reads run concurrently.
"""

import sqlite3
import threading
import json
import os
import re
import glob
from datetime import datetime

DB_PATH = os.path.join(os.getenv("CACHE_DIR", "/app/cache"), "cve_analyzer.db")

_conn: sqlite3.Connection | None = None
_write_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA cache_size=-32000")
    return _conn


def init_db():
    conn = _connect()
    with _write_lock:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id           TEXT PRIMARY KEY,
                name                TEXT NOT NULL,
                scanned_at          TEXT,
                bulk_scan           INTEGER DEFAULT 0,
                total_devices       INTEGER DEFAULT 0,
                vulnerable_devices  INTEGER DEFAULT 0,
                max_score           REAL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS devices (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id               TEXT NOT NULL,
                resource_name           TEXT NOT NULL,
                resource_category       TEXT,
                resource_type           TEXT,
                os                      TEXT,
                platform_name           TEXT,
                os_version              TEXT,
                serial                  TEXT,
                pon                     TEXT,
                highest_severity_score  REAL DEFAULT 0.0,
                is_vulnerable           INTEGER DEFAULT 0,
                llm_analysis            TEXT,
                scanned_at              TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS cves (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   INTEGER NOT NULL,
                cve_id      TEXT NOT NULL,
                score       REAL,
                severity    TEXT,
                description TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS summaries (
                tenant_id               TEXT PRIMARY KEY,
                risk_posture            TEXT,
                risk_summary            TEXT,
                trend                   TEXT,
                trend_detail            TEXT,
                recommendations_json    TEXT,
                top_cves_json           TEXT,
                generated_at            TEXT,
                previous_generated_at   TEXT,
                vulnerable_device_count INTEGER,
                total_device_count      INTEGER,
                max_severity_score      REAL,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_devices_tenant        ON devices(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_devices_score         ON devices(highest_severity_score DESC);
            CREATE INDEX IF NOT EXISTS idx_cves_device           ON cves(device_id);
            CREATE INDEX IF NOT EXISTS idx_cves_id               ON cves(cve_id);
            CREATE INDEX IF NOT EXISTS idx_tenants_score         ON tenants(max_score DESC, vulnerable_devices DESC);
        """)
        conn.commit()

        # Migrate existing tables: add new columns if absent
        existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        for col, typedef in [
            ("platform_name", "TEXT"),
            ("os_version",    "TEXT"),
            ("serial",        "TEXT"),
            ("pon",           "TEXT"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {typedef}")

        # Create index on platform_name after column is guaranteed to exist
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform_name)")

        # Best-effort backfill: set platform_name = everything in os before first
        # digit-led token (e.g. "FortiOS 7.4.2" → "FortiOS").
        # This only runs for rows that predate the new column — new scans populate
        # platform_name directly from NetBox.
        conn.execute("""
            UPDATE devices
            SET platform_name = TRIM(SUBSTR(os, 1,
                CASE
                    WHEN INSTR(os, ' ') > 0
                    THEN INSTR(os, ' ') - 1
                    ELSE LENGTH(os)
                END
            ))
            WHERE (platform_name IS NULL OR platform_name = '')
              AND os IS NOT NULL AND os != ''
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Tenant helpers
# ---------------------------------------------------------------------------

def get_tenant(tenant_id: str) -> dict:
    row = _connect().execute(
        "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    return dict(row) if row else {}


def get_cache_age_hours(tenant_id: str) -> float | None:
    row = _connect().execute(
        "SELECT scanned_at FROM tenants WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    if not row or not row["scanned_at"]:
        return None
    return (datetime.utcnow() - datetime.fromisoformat(row["scanned_at"])).total_seconds() / 3600


def list_recent_tenants(limit: int = 200) -> list[dict]:
    rows = _connect().execute("""
        SELECT tenant_id, name, scanned_at, total_devices, vulnerable_devices, max_score
        FROM tenants WHERE scanned_at IS NOT NULL
        ORDER BY scanned_at DESC LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Results read / write
# ---------------------------------------------------------------------------

def save_tenant_results(tenant_id: str, data: dict):
    """Persist a full scan result. Replaces existing devices for this tenant."""
    devices = data.get("devices", [])
    scanned_at = data.get("scanned_at") or datetime.utcnow().isoformat()
    name = data.get("tenant_name", f"Tenant {tenant_id}")
    bulk_scan = 1 if data.get("bulk_scan") else 0
    vulnerable = sum(1 for d in devices if d.get("is_vulnerable"))
    max_score = max((d.get("highest_severity_score", 0.0) for d in devices), default=0.0)

    conn = _connect()
    with _write_lock:
        conn.execute("BEGIN")
        try:
            conn.execute("DELETE FROM devices WHERE tenant_id = ?", (tenant_id,))
            conn.execute("""
                INSERT INTO tenants (tenant_id, name, scanned_at, bulk_scan,
                                     total_devices, vulnerable_devices, max_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    name=excluded.name, scanned_at=excluded.scanned_at,
                    bulk_scan=excluded.bulk_scan, total_devices=excluded.total_devices,
                    vulnerable_devices=excluded.vulnerable_devices, max_score=excluded.max_score
            """, (tenant_id, name, scanned_at, bulk_scan, len(devices), vulnerable, max_score))

            for dev in devices:
                cur = conn.execute("""
                    INSERT INTO devices
                        (tenant_id, resource_name, resource_category, resource_type,
                         os, platform_name, os_version, serial, pon,
                         highest_severity_score, is_vulnerable, llm_analysis, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tenant_id,
                    dev.get("resource_name"),
                    dev.get("resource_category"),
                    dev.get("resource_type"),
                    dev.get("os"),
                    dev.get("platform_name"),
                    dev.get("os_version"),
                    dev.get("serial"),
                    dev.get("pon"),
                    dev.get("highest_severity_score", 0.0),
                    1 if dev.get("is_vulnerable") else 0,
                    dev.get("llm_analysis"),
                    scanned_at,
                ))
                device_id = cur.lastrowid
                cve_rows = [
                    (device_id, c.get("id"), c.get("score"), c.get("severity"), c.get("description"))
                    for c in dev.get("cves", [])
                ]
                if cve_rows:
                    conn.executemany(
                        "INSERT INTO cves (device_id, cve_id, score, severity, description) VALUES (?,?,?,?,?)",
                        cve_rows,
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def load_tenant_results(tenant_id: str) -> dict:
    conn = _connect()
    tenant = get_tenant(tenant_id)
    if not tenant:
        return {}

    dev_rows = conn.execute(
        "SELECT * FROM devices WHERE tenant_id = ? ORDER BY highest_severity_score DESC",
        (tenant_id,),
    ).fetchall()

    devices = []
    if dev_rows:
        dev_ids = [r["id"] for r in dev_rows]
        placeholders = ",".join("?" * len(dev_ids))
        cve_rows = conn.execute(
            f"SELECT * FROM cves WHERE device_id IN ({placeholders})", dev_ids
        ).fetchall()
        cves_by_device: dict[int, list] = {}
        for c in cve_rows:
            cves_by_device.setdefault(c["device_id"], []).append({
                "id": c["cve_id"], "score": c["score"],
                "severity": c["severity"], "description": c["description"],
            })
        for dev in dev_rows:
            devices.append({
                "resource_name": dev["resource_name"],
                "resource_category": dev["resource_category"],
                "resource_type": dev["resource_type"],
                "os": dev["os"],
                "platform_name": dev["platform_name"],
                "os_version": dev["os_version"],
                "serial": dev["serial"],
                "pon": dev["pon"],
                "highest_severity_score": dev["highest_severity_score"],
                "is_vulnerable": bool(dev["is_vulnerable"]),
                "llm_analysis": dev["llm_analysis"],
                "cves": cves_by_device.get(dev["id"], []),
            })

    return {
        "tenant_id": tenant_id,
        "tenant_name": tenant["name"],
        "scanned_at": tenant["scanned_at"],
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def save_tenant_summary(tenant_id: str, data: dict):
    conn = _connect()
    with _write_lock:
        conn.execute("""
            INSERT INTO summaries
                (tenant_id, risk_posture, risk_summary, trend, trend_detail,
                 recommendations_json, top_cves_json, generated_at, previous_generated_at,
                 vulnerable_device_count, total_device_count, max_severity_score)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                risk_posture=excluded.risk_posture, risk_summary=excluded.risk_summary,
                trend=excluded.trend, trend_detail=excluded.trend_detail,
                recommendations_json=excluded.recommendations_json,
                top_cves_json=excluded.top_cves_json, generated_at=excluded.generated_at,
                previous_generated_at=excluded.previous_generated_at,
                vulnerable_device_count=excluded.vulnerable_device_count,
                total_device_count=excluded.total_device_count,
                max_severity_score=excluded.max_severity_score
        """, (
            tenant_id,
            data.get("risk_posture"),
            data.get("risk_summary"),
            data.get("trend"),
            data.get("trend_detail"),
            json.dumps(data.get("recommendations", [])),
            json.dumps(data.get("top_cves", [])),
            data.get("generated_at"),
            data.get("previous_generated_at"),
            data.get("vulnerable_device_count"),
            data.get("total_device_count"),
            data.get("max_severity_score"),
        ))
        conn.commit()


def load_tenant_summary(tenant_id: str) -> dict:
    row = _connect().execute(
        "SELECT * FROM summaries WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    if not row:
        return {}
    d = dict(row)
    d["recommendations"] = json.loads(d.pop("recommendations_json") or "[]")
    d["top_cves"] = json.loads(d.pop("top_cves_json") or "[]")
    return d


# ---------------------------------------------------------------------------
# Leaderboard
# ---------------------------------------------------------------------------

def get_leaderboard(limit: int = 100, min_devices: int = 1) -> list[dict]:
    rows = _connect().execute("""
        SELECT
            t.tenant_id, t.name, t.scanned_at, t.total_devices,
            t.vulnerable_devices, t.max_score,
            CASE WHEN t.total_devices > 0
                 THEN ROUND(100.0 * t.vulnerable_devices / t.total_devices, 1)
                 ELSE 0.0 END AS vuln_pct,
            s.risk_posture, s.trend
        FROM tenants t
        LEFT JOIN summaries s ON t.tenant_id = s.tenant_id
        WHERE t.total_devices >= ?
        ORDER BY t.max_score DESC, t.vulnerable_devices DESC, t.name ASC
        LIMIT ?
    """, (min_devices, limit)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Estate-wide stats (for landing page dashboard)
# ---------------------------------------------------------------------------

def get_estate_stats() -> dict:
    conn = _connect()
    row = conn.execute("""
        SELECT
            COUNT(DISTINCT tenant_id)               AS total_tenants,
            COUNT(*)                                AS total_devices,
            SUM(is_vulnerable)                      AS vulnerable_devices,
            MAX(highest_severity_score)             AS max_score,
            (SELECT COUNT(*) FROM cves)             AS total_cve_instances,
            (SELECT MAX(scanned_at) FROM tenants)   AS last_scan
        FROM devices
    """).fetchone()

    critical_devices = conn.execute("""
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN cves c ON d.id = c.device_id WHERE c.score >= 9.0
    """).fetchone()[0] or 0

    d = dict(row)
    d["critical_devices"] = critical_devices
    d["vulnerable_devices"] = d["vulnerable_devices"] or 0
    return d


def get_top_cves(limit: int = 20) -> list[dict]:
    """Most widespread CVEs across the entire estate."""
    rows = _connect().execute("""
        SELECT
            c.cve_id,
            MAX(c.score)                    AS score,
            MAX(c.severity)                 AS severity,
            COUNT(*)                        AS device_count,
            COUNT(DISTINCT d.tenant_id)     AS tenant_count,
            MAX(c.description)              AS description
        FROM cves c
        JOIN devices d ON c.device_id = d.id
        GROUP BY c.cve_id
        ORDER BY device_count DESC, score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_top_platforms(limit: int = 15) -> list[dict]:
    """OS platforms with the most vulnerable devices."""
    rows = _connect().execute("""
        SELECT
            COALESCE(NULLIF(platform_name,''), 'Unknown') AS platform,
            COUNT(*)                                       AS total_devices,
            SUM(is_vulnerable)                             AS vulnerable_devices,
            MAX(highest_severity_score)                    AS max_score,
            ROUND(100.0 * SUM(is_vulnerable) / COUNT(*), 1) AS vuln_pct
        FROM devices
        GROUP BY platform_name
        HAVING total_devices > 0
        ORDER BY vulnerable_devices DESC, max_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_top_device_types(limit: int = 15) -> list[dict]:
    """Device models/types with the most vulnerable units."""
    rows = _connect().execute("""
        SELECT
            COALESCE(NULLIF(resource_type,''), 'Unknown') AS device_type,
            resource_category,
            COUNT(*)                                       AS total_devices,
            SUM(is_vulnerable)                             AS vulnerable_devices,
            MAX(highest_severity_score)                    AS max_score
        FROM devices
        WHERE resource_type NOT IN ('Unknown Model','Unknown Cluster','')
          AND resource_type IS NOT NULL
        GROUP BY resource_type
        ORDER BY vulnerable_devices DESC, max_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_severity_breakdown() -> dict:
    """Count of CVE instances by severity band across the whole estate."""
    rows = _connect().execute("""
        SELECT UPPER(COALESCE(severity,'UNKNOWN')) AS sev, COUNT(*) AS cnt
        FROM cves GROUP BY sev ORDER BY cnt DESC
    """).fetchall()
    return {r["sev"]: r["cnt"] for r in rows}


# ---------------------------------------------------------------------------
# LLM back-fill helpers
# ---------------------------------------------------------------------------

# Placeholder text set by the global scan — signals that real analysis is needed.
_PENDING_ANALYSIS_PLACEHOLDERS = frozenset({
    'Vulnerabilities found — open this tenant for AI analysis.',
    'Analyzing vulnerabilities...',
    'Scanning...',
})


def get_tenants_needing_analysis(limit: int = 20) -> list[dict]:
    """
    Return tenants that need LLM back-fill work: either they have no estate
    summary yet, or they have vulnerable devices whose analysis is still a
    placeholder string from the bulk scan.
    Ordered by most vulnerable devices first so critical clients get attention
    before smaller ones.
    """
    placeholders = tuple(_PENDING_ANALYSIS_PLACEHOLDERS)
    ph_sql = ','.join('?' * len(placeholders))
    rows = _connect().execute(f"""
        SELECT
            t.tenant_id,
            t.name,
            t.total_devices,
            t.vulnerable_devices,
            CASE WHEN s.risk_posture IS NULL THEN 1 ELSE 0 END AS needs_summary,
            (
                SELECT COUNT(*) FROM devices d
                WHERE d.tenant_id = t.tenant_id
                  AND d.is_vulnerable = 1
                  AND (d.llm_analysis IS NULL OR d.llm_analysis IN ({ph_sql}))
            ) AS pending_devices
        FROM tenants t
        LEFT JOIN summaries s ON t.tenant_id = s.tenant_id
        WHERE t.scanned_at IS NOT NULL
          AND t.total_devices > 0
          AND (
              s.risk_posture IS NULL
              OR (
                  SELECT COUNT(*) FROM devices d
                  WHERE d.tenant_id = t.tenant_id
                    AND d.is_vulnerable = 1
                    AND (d.llm_analysis IS NULL OR d.llm_analysis IN ({ph_sql}))
              ) > 0
          )
        ORDER BY t.vulnerable_devices DESC, t.scanned_at DESC
        LIMIT ?
    """, (*placeholders, *placeholders, limit)).fetchall()
    return [dict(r) for r in rows]


def get_devices_needing_llm(tenant_id: str) -> list[dict]:
    """Return vulnerable devices for a tenant whose LLM analysis is still a placeholder."""
    placeholders = tuple(_PENDING_ANALYSIS_PLACEHOLDERS)
    ph_sql = ','.join('?' * len(placeholders))
    rows = _connect().execute(f"""
        SELECT d.id, d.resource_name, d.resource_type, d.os,
               d.platform_name, d.os_version, d.highest_severity_score
        FROM devices d
        WHERE d.tenant_id = ?
          AND d.is_vulnerable = 1
          AND (d.llm_analysis IS NULL OR d.llm_analysis IN ({ph_sql}))
        ORDER BY d.highest_severity_score DESC
    """, (tenant_id, *placeholders)).fetchall()
    return [dict(r) for r in rows]


def update_device_llm_analysis(tenant_id: str, resource_name: str, llm_analysis: str):
    """Update the LLM analysis text for a single device row."""
    conn = _connect()
    with _write_lock:
        conn.execute(
            "UPDATE devices SET llm_analysis = ? WHERE tenant_id = ? AND resource_name = ?",
            (llm_analysis, tenant_id, resource_name),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Export data
# ---------------------------------------------------------------------------

def get_export_rows(tenant_id: str | None = None) -> list[dict]:
    """
    Return one row per device suitable for Excel export.
    Pass tenant_id to limit to a single tenant, or None for all.
    """
    if tenant_id:
        where = "WHERE d.tenant_id = ? AND d.highest_severity_score > 0"
        params = (tenant_id,)
    else:
        where = "WHERE d.highest_severity_score > 0"
        params = ()
    rows = _connect().execute(f"""
        SELECT
            t.name                      AS tenant_name,
            d.resource_name,
            d.pon,
            d.platform_name,
            d.resource_type             AS device_type,
            d.os_version                AS current_firmware,
            d.serial,
            d.highest_severity_score    AS cve_score,
            d.resource_category,
            COUNT(c.id)                 AS cve_count
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        LEFT JOIN cves c ON d.id = c.device_id
        {where}
        GROUP BY d.id
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """, params).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# One-time JSON → SQLite migration
# ---------------------------------------------------------------------------

def migrate_from_json(cache_dir: str) -> int:
    migrated = 0
    conn = _connect()

    for fpath in glob.glob(os.path.join(cache_dir, "tenant_*_results.json")):
        fname = os.path.basename(fpath)
        tid = fname[len("tenant_"):-len("_results.json")]

        existing = conn.execute(
            "SELECT 1 FROM tenants WHERE tenant_id = ?", (tid,)
        ).fetchone()
        if existing:
            continue

        try:
            with open(fpath) as f:
                data = json.load(f)
            save_tenant_results(tid, data)

            summary_path = os.path.join(cache_dir, f"tenant_{tid}_summary.json")
            if os.path.exists(summary_path):
                with open(summary_path) as f:
                    summary = json.load(f)
                save_tenant_summary(tid, summary)

            migrated += 1
        except Exception as e:
            print(f"  ⚠️  Migration failed for {fname}: {e}")

    if migrated:
        print(f"✅ Migrated {migrated} JSON cache(s) → SQLite")
    return migrated
