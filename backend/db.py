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

_local = threading.local()
_write_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    """Return a per-thread SQLite connection (thread-local, WAL mode)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=True, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-32000")
        _local.conn = conn
    return conn


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
            ("platform_name",            "TEXT"),
            ("os_version",               "TEXT"),
            ("recommended_version",      "TEXT"),
            ("serial",                   "TEXT"),
            ("pon",                      "TEXT"),
            # GIA engineering-recommended version
            ("gia_recommended_version",  "TEXT"),
            # FBA config-analysis columns
            ("fba_scanned_at",           "TEXT"),
            ("fba_analyzed",             "INTEGER"),
            ("fba_vulnerable",           "INTEGER"),
            ("fba_vuln_acl",             "INTEGER"),
            ("fba_vuln_password",        "INTEGER"),
            ("fba_reason",               "TEXT"),
            ("fba_findings",             "TEXT"),
            ("fba_error",                "INTEGER"),
            ("fba_config_url",           "TEXT"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {typedef}")

        # Config-aware CVE applicability. Keyed by device NAME, not devices.id:
        # save_tenant_results() deletes and re-inserts device rows on every scan,
        # and configs / verdicts must survive that.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS device_configs (
                resource_name   TEXT PRIMARY KEY COLLATE NOCASE,
                source          TEXT NOT NULL,
                content         TEXT NOT NULL,
                content_hash    TEXT NOT NULL,
                style           TEXT,
                line_count      INTEGER,
                redactions      INTEGER,
                fetched_at      TEXT NOT NULL,
                checked_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cve_requirements (
                cve_id            TEXT NOT NULL,
                platform          TEXT NOT NULL COLLATE NOCASE,
                requirements_json TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                PRIMARY KEY (cve_id, platform)
            );

            CREATE TABLE IF NOT EXISTS cve_config_verdicts (
                resource_name    TEXT NOT NULL COLLATE NOCASE,
                cve_id           TEXT NOT NULL,
                config_hash      TEXT NOT NULL,
                verdict          TEXT NOT NULL,
                rationale        TEXT,
                evidence_json    TEXT,
                absent_json      TEXT,
                suggested_change TEXT,
                change_note      TEXT,
                analyzed_at      TEXT NOT NULL,
                PRIMARY KEY (resource_name, cve_id)
            );
        """)

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
                         os, platform_name, os_version, recommended_version,
                         gia_recommended_version, serial, pon,
                         highest_severity_score, is_vulnerable, llm_analysis, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tenant_id,
                    dev.get("resource_name"),
                    dev.get("resource_category"),
                    dev.get("resource_type"),
                    dev.get("os"),
                    dev.get("platform_name"),
                    dev.get("os_version"),
                    dev.get("recommended_version"),
                    dev.get("gia_recommended_version"),
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
                "gia_recommended_version": dev["gia_recommended_version"],
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

def get_all_tenants() -> list[dict]:
    """Return every tenant row, sorted alphabetically. No limit, no device-count filter."""
    rows = _connect().execute("""
        SELECT tenant_id, name, total_devices
        FROM tenants
        ORDER BY name ASC
    """).fetchall()
    return [dict(r) for r in rows]


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
# FBA (Firewall Baseline Analysis) helpers
# ---------------------------------------------------------------------------

def get_devices_needing_fba_refresh(max_age_hours: int = 24) -> list[dict]:
    """Return all devices whose FBA data is absent or older than max_age_hours."""
    rows = _connect().execute("""
        SELECT d.id, d.resource_name, t.name AS tenant_name
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        WHERE d.fba_scanned_at IS NULL
           OR datetime(d.fba_scanned_at) < datetime('now', ? || ' hours')
        ORDER BY d.resource_name ASC
    """, (f"-{max_age_hours}",)).fetchall()
    return [dict(r) for r in rows]


def update_device_fba(device_id: int, data: dict | None, scanned_at: str) -> None:
    """
    Persist FBA result for a device.
    data=None means no config was found (fba_error=1, fba_analyzed=0).
    """
    import json as _json
    with _write_lock:
        if data is None:
            _connect().execute("""
                UPDATE devices
                SET fba_scanned_at=?, fba_analyzed=0, fba_vulnerable=NULL,
                    fba_vuln_acl=NULL, fba_vuln_password=NULL,
                    fba_reason=NULL, fba_findings=NULL, fba_error=1,
                    fba_config_url=NULL
                WHERE id=?
            """, (scanned_at, device_id))
        else:
            findings_json = _json.dumps(data.get("findings") or [])
            _connect().execute("""
                UPDATE devices
                SET fba_scanned_at=?,
                    fba_analyzed=?,
                    fba_vulnerable=?,
                    fba_vuln_acl=?,
                    fba_vuln_password=?,
                    fba_reason=?,
                    fba_findings=?,
                    fba_config_url=?,
                    fba_error=0
                WHERE id=?
            """, (
                scanned_at,
                1 if data.get("analyzed") else 0,
                1 if data.get("vulnerable") else 0,
                1 if data.get("vuln_acl") else 0,
                1 if data.get("vuln_password") else 0,
                data.get("reason"),
                findings_json,
                data.get("config_url"),
                device_id,
            ))
        _connect().commit()


def get_device_fba_by_name(resource_name: str) -> dict | None:
    """Return stored FBA data for a device by its resource_name."""
    import json as _json
    row = _connect().execute("""
        SELECT fba_scanned_at, fba_analyzed, fba_vulnerable, fba_vuln_acl,
               fba_vuln_password, fba_reason, fba_findings, fba_error
        FROM devices WHERE resource_name = ?
        LIMIT 1
    """, (resource_name,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("fba_findings"):
        try:
            d["fba_findings"] = _json.loads(d["fba_findings"])
        except Exception:
            d["fba_findings"] = []
    return d


# ---------------------------------------------------------------------------
# Config-aware CVE applicability (device configs, CVE requirements, verdicts)
# ---------------------------------------------------------------------------

def get_device_config(resource_name: str, with_content: bool = True) -> dict | None:
    cols = "*" if with_content else (
        "resource_name, source, content_hash, style, line_count, redactions, fetched_at, checked_at"
    )
    row = _connect().execute(
        f"SELECT {cols} FROM device_configs WHERE resource_name = ?", (resource_name,)
    ).fetchone()
    return dict(row) if row else None


def upsert_device_config(resource_name: str, source: str, content: str, content_hash: str,
                         style: str, redactions: int, now: str) -> bool:
    """Store an already-REDACTED config. Returns True when the content changed
    (new device or new hash); an identical re-fetch only bumps checked_at."""
    conn = _connect()
    with _write_lock:
        row = conn.execute(
            "SELECT content_hash FROM device_configs WHERE resource_name = ?", (resource_name,)
        ).fetchone()
        if row and row["content_hash"] == content_hash:
            conn.execute(
                "UPDATE device_configs SET checked_at = ? WHERE resource_name = ?",
                (now, resource_name),
            )
            conn.commit()
            return False
        conn.execute("""
            INSERT INTO device_configs
                (resource_name, source, content, content_hash, style, line_count,
                 redactions, fetched_at, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource_name) DO UPDATE SET
                source=excluded.source, content=excluded.content,
                content_hash=excluded.content_hash, style=excluded.style,
                line_count=excluded.line_count, redactions=excluded.redactions,
                fetched_at=excluded.fetched_at, checked_at=excluded.checked_at
        """, (resource_name, source, content, content_hash, style,
              content.count("\n") + 1, redactions, now, now))
        conn.commit()
        return True


def touch_device_config(resource_name: str, now: str) -> None:
    with _write_lock:
        _connect().execute(
            "UPDATE device_configs SET checked_at = ? WHERE resource_name = ?", (now, resource_name)
        )
        _connect().commit()


def get_devices_needing_config_fetch(max_age_hours: int = 24, limit: int = 50) -> list[dict]:
    """Vulnerable devices FBA holds a config for, whose stored copy is missing or
    stale. A config pushed by a Halo instance (source='push') is never overwritten
    by the FBA copy — the explicit push wins."""
    rows = _connect().execute("""
        SELECT d.resource_name, MAX(d.fba_config_url) AS fba_config_url
        FROM devices d
        LEFT JOIN device_configs dc ON dc.resource_name = d.resource_name
        WHERE d.is_vulnerable = 1
          AND d.fba_config_url IS NOT NULL AND d.fba_config_url != ''
          AND (dc.resource_name IS NULL
               OR (dc.source = 'fba'
                   AND datetime(dc.checked_at) < datetime('now', ? || ' hours')))
        GROUP BY d.resource_name
        ORDER BY MAX(d.highest_severity_score) DESC
        LIMIT ?
    """, (f"-{max_age_hours}", limit)).fetchall()
    return [dict(r) for r in rows]


def get_devices_needing_cve_assessment(limit: int = 10) -> list[dict]:
    """Devices that have a stored config and at least one CVE with no verdict
    for the CURRENT config hash (new CVE, or the config changed)."""
    rows = _connect().execute("""
        SELECT d.id, d.resource_name, d.resource_type, d.os, d.platform_name,
               d.highest_severity_score, dc.content_hash
        FROM device_configs dc
        JOIN devices d ON dc.resource_name = d.resource_name
        WHERE d.is_vulnerable = 1
          AND EXISTS (
              SELECT 1 FROM cves c
              WHERE c.device_id = d.id
                AND NOT EXISTS (
                    SELECT 1 FROM cve_config_verdicts v
                    WHERE v.resource_name = d.resource_name
                      AND v.cve_id = c.cve_id
                      AND v.config_hash = dc.content_hash
                )
          )
        GROUP BY d.resource_name
        ORDER BY d.highest_severity_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_device_cves(device_id: int) -> list[dict]:
    rows = _connect().execute(
        "SELECT cve_id AS id, score, severity, description FROM cves "
        "WHERE device_id = ? ORDER BY score DESC", (device_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_cve_requirements(cve_ids: list[str], platform: str) -> dict[str, dict]:
    import json as _json
    out = {}
    conn = _connect()
    for i in range(0, len(cve_ids), 500):
        chunk = cve_ids[i:i + 500]
        ph = ",".join("?" * len(chunk))
        for r in conn.execute(
            f"SELECT cve_id, requirements_json FROM cve_requirements "
            f"WHERE platform = ? AND cve_id IN ({ph})", (platform, *chunk)
        ):
            try:
                out[r["cve_id"]] = _json.loads(r["requirements_json"])
            except Exception:
                pass
    return out


def save_cve_requirements(platform: str, requirements: dict[str, dict], now: str) -> None:
    import json as _json
    if not requirements:
        return
    with _write_lock:
        _connect().executemany(
            "INSERT OR REPLACE INTO cve_requirements (cve_id, platform, requirements_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            [(cid, platform, _json.dumps(req), now) for cid, req in requirements.items()],
        )
        _connect().commit()


def save_cve_verdicts(resource_name: str, config_hash: str, rows: list[dict], now: str) -> None:
    import json as _json
    if not rows:
        return
    with _write_lock:
        _connect().executemany("""
            INSERT OR REPLACE INTO cve_config_verdicts
                (resource_name, cve_id, config_hash, verdict, rationale, evidence_json,
                 absent_json, suggested_change, change_note, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [(
            resource_name, r["cve_id"], config_hash, r["verdict"], r.get("rationale"),
            _json.dumps(r.get("evidence") or []), _json.dumps(r.get("absent_sections") or []),
            r.get("suggested_change") or "", r.get("change_note") or "", now,
        ) for r in rows])
        _connect().commit()


def get_cve_verdicts(resource_name: str) -> dict[str, dict]:
    """{cve_id: verdict row} for a device. `stale` marks verdicts computed
    against an older config than the one currently stored."""
    import json as _json
    cfg = get_device_config(resource_name, with_content=False)
    current = cfg["content_hash"] if cfg else None
    out = {}
    for r in _connect().execute(
        "SELECT * FROM cve_config_verdicts WHERE resource_name = ?", (resource_name,)
    ):
        d = dict(r)
        for src, dst in (("evidence_json", "evidence"), ("absent_json", "absent_sections")):
            try:
                d[dst] = _json.loads(d.pop(src) or "[]")
            except Exception:
                d[dst] = []
        d["stale"] = d.pop("config_hash") != current
        d.pop("resource_name", None)
        out[d["cve_id"]] = d
    return out


def get_config_applicability_counts() -> dict:
    conn = _connect()
    configs = conn.execute(
        "SELECT source, COUNT(*) AS n FROM device_configs GROUP BY source"
    ).fetchall()
    verdicts = conn.execute(
        "SELECT verdict, COUNT(*) AS n FROM cve_config_verdicts GROUP BY verdict"
    ).fetchall()
    return {
        "configs_by_source": {r["source"]: r["n"] for r in configs},
        "verdicts": {r["verdict"]: r["n"] for r in verdicts},
    }


# ---------------------------------------------------------------------------
# Drilldown queries (device lists for dashboard widget click-through)
# ---------------------------------------------------------------------------

_DRILLDOWN_COLS = """
    t.name                      AS tenant_name,
    d.resource_name,
    d.pon,
    d.platform_name,
    d.resource_type             AS device_type,
    d.os_version                AS current_firmware,
    d.recommended_version,
    d.gia_recommended_version,
    d.serial,
    d.highest_severity_score    AS cve_score,
    d.resource_category,
    d.fba_vulnerable,
    d.fba_error,
    d.fba_analyzed,
    (SELECT COUNT(*) FROM cves c2 WHERE c2.device_id = d.id) AS cve_count
"""


def get_devices_by_severity(severity: str) -> list[dict]:
    rows = _connect().execute(f"""
        SELECT DISTINCT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        JOIN cves c ON c.device_id = d.id
        WHERE UPPER(c.severity) = ?
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """, (severity.upper(),)).fetchall()
    return [dict(r) for r in rows]


def get_devices_by_platform(platform: str) -> list[dict]:
    rows = _connect().execute(f"""
        SELECT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        WHERE d.platform_name = ? AND d.is_vulnerable = 1
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """, (platform,)).fetchall()
    return [dict(r) for r in rows]


def get_devices_by_cve(cve_id: str) -> list[dict]:
    rows = _connect().execute(f"""
        SELECT DISTINCT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        JOIN cves c ON c.device_id = d.id
        WHERE c.cve_id = ?
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """, (cve_id,)).fetchall()
    return [dict(r) for r in rows]


def get_all_clients_detail() -> list[dict]:
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
        WHERE t.total_devices > 0
        ORDER BY t.name ASC
    """).fetchall()
    return [dict(r) for r in rows]


def get_all_devices_list() -> list[dict]:
    rows = _connect().execute(f"""
        SELECT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_vulnerable_devices() -> list[dict]:
    rows = _connect().execute(f"""
        SELECT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        WHERE d.is_vulnerable = 1
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_critical_devices() -> list[dict]:
    rows = _connect().execute(f"""
        SELECT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        WHERE d.highest_severity_score >= 9.0
        ORDER BY t.name ASC, d.highest_severity_score DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_all_cve_instances() -> list[dict]:
    rows = _connect().execute("""
        SELECT
            t.name          AS tenant_name,
            d.resource_name,
            d.platform_name,
            d.os_version    AS current_firmware,
            c.cve_id,
            c.score,
            c.severity,
            c.description
        FROM cves c
        JOIN devices d ON c.device_id = d.id
        JOIN tenants t ON d.tenant_id = t.tenant_id
        ORDER BY t.name ASC, c.score DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_devices_at_peak_score() -> list[dict]:
    conn = _connect()
    peak = conn.execute("SELECT MAX(highest_severity_score) FROM devices").fetchone()[0]
    if not peak:
        return []
    rows = conn.execute(f"""
        SELECT {_DRILLDOWN_COLS}
        FROM devices d
        JOIN tenants t ON d.tenant_id = t.tenant_id
        WHERE d.highest_severity_score = ?
        ORDER BY t.name ASC, d.resource_name ASC
    """, (peak,)).fetchall()
    return [dict(r) for r in rows]


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
            d.recommended_version,
            d.gia_recommended_version,
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
