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
                recommended_version     TEXT,
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

            CREATE TABLE IF NOT EXISTS notifications (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                config      TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at          TEXT NOT NULL,
                scan_type           TEXT DEFAULT 'global',
                duration_seconds    REAL,
                total_tenants       INTEGER,
                total_devices       INTEGER,
                physical_devices    INTEGER,
                virtual_machines    INTEGER,
                vulnerable_devices  INTEGER,
                critical_devices    INTEGER,
                high_devices        INTEGER,
                total_cves          INTEGER,
                peak_score          REAL,
                nvd_queried         INTEGER,
                nvd_cached          INTEGER,
                nvd_total           INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_at ON scan_history(scanned_at DESC);

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
            ("platform_name",       "TEXT"),
            ("os_version",          "TEXT"),
            ("recommended_version", "TEXT"),
            ("serial",              "TEXT"),
            ("pon",                 "TEXT"),
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
                         os, platform_name, os_version, recommended_version, serial, pon,
                         highest_severity_score, is_vulnerable, llm_analysis, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tenant_id,
                    dev.get("resource_name"),
                    dev.get("resource_category"),
                    dev.get("resource_type"),
                    dev.get("os"),
                    dev.get("platform_name"),
                    dev.get("os_version"),
                    dev.get("recommended_version"),
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
                "recommended_version": dev["recommended_version"],
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
            COUNT(DISTINCT tenant_id)                                           AS total_tenants,
            COUNT(*)                                                             AS total_devices,
            SUM(CASE WHEN resource_category = 'device' THEN 1 ELSE 0 END)      AS physical_devices,
            SUM(CASE WHEN resource_category = 'vm'     THEN 1 ELSE 0 END)      AS virtual_machines,
            SUM(is_vulnerable)                                                   AS vulnerable_devices,
            MAX(highest_severity_score)                                          AS max_score,
            (SELECT COUNT(*) FROM cves)                                          AS total_cve_instances,
            (SELECT MAX(scanned_at) FROM tenants)                                AS last_scan
        FROM devices
    """).fetchone()

    critical_devices = conn.execute("""
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN cves c ON d.id = c.device_id WHERE c.score >= 9.0
    """).fetchone()[0] or 0

    d = dict(row)
    d["critical_devices"] = critical_devices
    d["vulnerable_devices"] = d["vulnerable_devices"] or 0
    d["physical_devices"]   = d["physical_devices"] or 0
    d["virtual_machines"]   = d["virtual_machines"] or 0
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

def get_vendors_for_tenants(tenant_ids: list) -> list:
    """Return distinct non-empty platform_name values for the given tenants, or all if empty."""
    conn = _connect()
    if tenant_ids:
        placeholders = ','.join('?' * len(tenant_ids))
        rows = conn.execute(f"""
            SELECT DISTINCT platform_name FROM devices
            WHERE tenant_id IN ({placeholders})
              AND platform_name IS NOT NULL AND platform_name != ''
            ORDER BY platform_name
        """, list(tenant_ids)).fetchall()
    else:
        rows = conn.execute("""
            SELECT DISTINCT platform_name FROM devices
            WHERE platform_name IS NOT NULL AND platform_name != ''
            ORDER BY platform_name
        """).fetchall()
    return [r[0] for r in rows]


def get_export_rows(
    tenant_id: str | None = None,
    tenant_ids: list | None = None,
    platforms: list | None = None,
) -> list[dict]:
    """
    Return one row per device suitable for Excel export.
    - tenant_id: single-tenant export (per-tenant download)
    - tenant_ids: filter to a list of tenants (notification filters)
    - platforms: filter to specific platform_names (notification filters)
    Pass all None/empty for the full estate.
    """
    conditions = ["d.highest_severity_score > 0"]
    params: list = []

    if tenant_id:
        conditions.append("d.tenant_id = ?")
        params.append(tenant_id)
    elif tenant_ids:
        placeholders = ','.join('?' * len(tenant_ids))
        conditions.append(f"d.tenant_id IN ({placeholders})")
        params.extend(tenant_ids)

    if platforms:
        placeholders = ','.join('?' * len(platforms))
        conditions.append(f"d.platform_name IN ({placeholders})")
        params.extend(platforms)

    where = "WHERE " + " AND ".join(conditions)
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


# ---------------------------------------------------------------------------
# Scan history / trending
# ---------------------------------------------------------------------------

def record_scan_snapshot(data: dict):
    """Append one row to scan_history after a scan completes."""
    conn = _connect()
    with _write_lock:
        conn.execute("""
            INSERT INTO scan_history
                (scanned_at, scan_type, duration_seconds, total_tenants,
                 total_devices, physical_devices, virtual_machines,
                 vulnerable_devices, critical_devices, high_devices,
                 total_cves, peak_score, nvd_queried, nvd_cached, nvd_total)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data.get("scanned_at"),
            data.get("scan_type", "global"),
            data.get("duration_seconds"),
            data.get("total_tenants"),
            data.get("total_devices"),
            data.get("physical_devices"),
            data.get("virtual_machines"),
            data.get("vulnerable_devices"),
            data.get("critical_devices"),
            data.get("high_devices"),
            data.get("total_cves"),
            data.get("peak_score"),
            data.get("nvd_queried"),
            data.get("nvd_cached"),
            data.get("nvd_total"),
        ))
        conn.commit()


def get_scan_history(limit: int = 20) -> list[dict]:
    rows = _connect().execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_scan_trends() -> dict:
    """Return the two most recent scan snapshots plus computed deltas."""
    rows = _connect().execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT 2"
    ).fetchall()
    if not rows:
        return {"current": None, "previous": None, "deltas": {}}

    current = dict(rows[0])
    previous = dict(rows[1]) if len(rows) > 1 else None

    if not previous:
        return {"current": current, "previous": None, "deltas": {}}

    int_keys = [
        "total_tenants", "total_devices", "physical_devices", "virtual_machines",
        "vulnerable_devices", "critical_devices", "high_devices", "total_cves",
        "nvd_queried", "nvd_cached", "nvd_total",
    ]
    float_keys = ["peak_score", "duration_seconds"]

    deltas: dict = {}
    for k in int_keys:
        deltas[k] = int(current.get(k) or 0) - int(previous.get(k) or 0)
    for k in float_keys:
        deltas[k] = round(float(current.get(k) or 0.0) - float(previous.get(k) or 0.0), 2)

    return {"current": current, "previous": previous, "deltas": deltas}


# ---------------------------------------------------------------------------
# Notification CRUD
# ---------------------------------------------------------------------------

DEFAULT_NOTIFICATION_CONFIG = {
    "enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_tls": "starttls",   # "none" | "starttls" | "tls"
    "smtp_username": "",
    "smtp_password": "",
    "from_address": "",
    "to_addresses": [],
    "cc_addresses": [],
    "bcc_addresses": [],
    "subject": "Defense Halo CVE Report — {date}",
    "body_preamble": "",
    "schedule_frequency": "daily",    # "daily" | "weekly" | "monthly"
    "schedule_time_utc": "00:00",
    "schedule_day_of_week": 1,        # 1=Mon … 7=Sun (weekly only)
    "schedule_day_of_month": 1,       # 1-31 (monthly only)
    "last_sent_at": None,
    "filter_tenant_ids": [],          # [] = all tenants
    "filter_platforms": [],           # [] = all platforms
}


def list_notifications() -> list[dict]:
    rows = _connect().execute(
        "SELECT id, name, config, updated_at FROM notifications ORDER BY updated_at ASC"
    ).fetchall()
    result = []
    for row in rows:
        cfg = json.loads(row["config"])
        result.append({"id": row["id"], "name": row["name"], "updated_at": row["updated_at"], **cfg})
    return result


def get_notification(notification_id: str) -> dict | None:
    row = _connect().execute(
        "SELECT id, name, config, updated_at FROM notifications WHERE id = ?",
        (notification_id,)
    ).fetchone()
    if not row:
        return None
    cfg = json.loads(row["config"])
    return {"id": row["id"], "name": row["name"], "updated_at": row["updated_at"], **cfg}


def save_notification(data: dict) -> dict:
    """Insert or update a notification. Generates an id if absent."""
    import uuid
    nid  = data.get("id") or str(uuid.uuid4())
    name = data.get("name", "Untitled Notification")
    now  = datetime.utcnow().isoformat()

    # Separate display fields from the config blob
    cfg = {k: v for k, v in data.items() if k not in ("id", "name", "updated_at")}
    # Preserve last_sent_at from existing record if not supplied
    existing = get_notification(nid)
    if existing and "last_sent_at" not in data:
        cfg["last_sent_at"] = existing.get("last_sent_at")

    with _write_lock:
        _connect().execute(
            """INSERT INTO notifications (id, name, config, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   name       = excluded.name,
                   config     = excluded.config,
                   updated_at = excluded.updated_at""",
            (nid, name, json.dumps(cfg), now)
        )
        _connect().commit()

    return get_notification(nid)


def delete_notification(notification_id: str) -> bool:
    with _write_lock:
        cur = _connect().execute(
            "DELETE FROM notifications WHERE id = ?", (notification_id,)
        )
        _connect().commit()
    return cur.rowcount > 0


def update_notification_sent(notification_id: str, sent_at: str):
    """Record the last successful send timestamp without touching other fields."""
    row = _connect().execute(
        "SELECT config FROM notifications WHERE id = ?", (notification_id,)
    ).fetchone()
    if not row:
        return
    cfg = json.loads(row["config"])
    cfg["last_sent_at"] = sent_at
    with _write_lock:
        _connect().execute(
            "UPDATE notifications SET config = ? WHERE id = ?",
            (json.dumps(cfg), notification_id)
        )
        _connect().commit()
