"""DB-layer tests for config-aware CVE applicability (temp SQLite file)."""

import os
import sys
import tempfile

os.environ["CACHE_DIR"] = tempfile.mkdtemp(prefix="sentinel-test-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402

NOW = "2026-09-21T00:00:00+00:00"


def _scan(cves):
    db.save_tenant_results("t1", {"tenant_name": "Acme", "devices": [{
        "resource_name": "Edge-FW-01", "resource_type": "FortiGate-60F", "os": "FortiOS 7.2.5",
        "platform_name": "FortiOS", "highest_severity_score": 9.8, "is_vulnerable": True,
        "cves": [{"id": c, "score": 9.8, "severity": "CRITICAL", "description": "x"} for c in cves],
    }]})


def _fresh():
    """Empty every table — tests share one SQLite file, and FBA data / verdicts
    deliberately survive rescans, so state would otherwise leak between tests."""
    db.init_db()
    conn = db._connect()
    for table in ("cve_config_verdicts", "device_configs", "cve_requirements", "devices", "tenants"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()


def _verdict(cve_id, verdict="exploitable"):
    return {"cve_id": cve_id, "verdict": verdict, "rationale": "r",
            "evidence": [{"section": "s", "start_line": 1, "end_line": 2, "snippet": "a\nb", "note": ""}],
            "absent_sections": [], "suggested_change": "config x\nend", "change_note": "n"}


def test_queue_lifecycle():
    db.init_db()
    _scan(["CVE-1", "CVE-2"])

    # no config yet → nothing to assess
    assert db.get_devices_needing_cve_assessment() == []

    # device name match is case-insensitive (Halo pushes NetBox names verbatim)
    assert db.upsert_device_config("edge-fw-01", "push", "config a\nend", "hash-A", "fortios", 0, NOW)
    assert not db.upsert_device_config("edge-fw-01", "push", "config a\nend", "hash-A", "fortios", 0, NOW)
    [dev] = db.get_devices_needing_cve_assessment()
    assert dev["resource_name"] == "Edge-FW-01" and dev["content_hash"] == "hash-A"
    assert [c["id"] for c in db.get_device_cves(dev["id"])] == ["CVE-1", "CVE-2"]

    # partial verdicts → still queued; full → drained
    db.save_cve_verdicts("Edge-FW-01", "hash-A", [_verdict("CVE-1")], NOW)
    assert len(db.get_devices_needing_cve_assessment()) == 1
    db.save_cve_verdicts("Edge-FW-01", "hash-A", [_verdict("CVE-2", "not_applicable")], NOW)
    assert db.get_devices_needing_cve_assessment() == []

    got = db.get_cve_verdicts("Edge-FW-01")
    assert got["CVE-1"]["evidence"][0]["snippet"] == "a\nb" and got["CVE-1"]["stale"] is False

    # a rescan deletes/re-inserts device rows — verdicts must survive it
    _scan(["CVE-1", "CVE-2"])
    assert db.get_devices_needing_cve_assessment() == []
    assert set(db.get_cve_verdicts("Edge-FW-01")) == {"CVE-1", "CVE-2"}

    # a newly matched CVE re-queues the device
    _scan(["CVE-1", "CVE-2", "CVE-3"])
    assert len(db.get_devices_needing_cve_assessment()) == 1
    db.save_cve_verdicts("Edge-FW-01", "hash-A", [_verdict("CVE-3")], NOW)

    # a changed config re-queues it and marks old verdicts stale
    assert db.upsert_device_config("Edge-FW-01", "push", "config b\nend", "hash-B", "fortios", 0, NOW)
    assert len(db.get_devices_needing_cve_assessment()) == 1
    assert db.get_cve_verdicts("Edge-FW-01")["CVE-1"]["stale"] is True


def test_requirements_cache_is_per_platform():
    db.init_db()
    db.save_cve_requirements("FortiOS", {"CVE-1": {"requires": "ssl-vpn"}}, NOW)
    assert db.get_cve_requirements(["CVE-1", "CVE-2"], "fortios") == {"CVE-1": {"requires": "ssl-vpn"}}
    assert db.get_cve_requirements(["CVE-1"], "IOS-XE") == {}


def test_fba_fetch_queue_respects_pushed_configs():
    db.init_db()
    _scan(["CVE-1"])
    dev_id = db._connect().execute("SELECT id FROM devices").fetchone()["id"]
    db.update_device_fba(dev_id, {"analyzed": True, "config_url": "https://fba/config/x.conf"}, NOW)
    # a pushed config exists (from the test above) → FBA must not overwrite it
    assert db.get_device_config("Edge-FW-01", with_content=False)["source"] == "push"
    assert db.get_devices_needing_config_fetch() == []
    db._connect().execute("DELETE FROM device_configs")
    db._connect().commit()
    [row] = db.get_devices_needing_config_fetch()
    assert row["fba_config_url"] == "https://fba/config/x.conf"


def test_fba_data_survives_rescan_and_states():
    _fresh()
    _scan(["CVE-1"])
    dev_id = db._connect().execute("SELECT id FROM devices").fetchone()["id"]
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "pending"

    # a failed lookup is not "not found", keeps the device out of the queue for the
    # retry window, and never clobbers good data
    db.mark_fba_lookup_failed(dev_id, "2099-01-01T00:00:00+00:00")
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "lookup_failed"
    assert db.get_devices_needing_fba_refresh(24, 1) == []

    db.update_device_fba(dev_id, {"analyzed": True, "vulnerable": False, "findings": [{"issue": "x"}],
                                  "config_url": "https://fba/config/x.conf"}, NOW)
    got = db.get_device_fba_by_name("Edge-FW-01")
    assert got["fba_state"] == "analyzed" and got["fba_lookup_failed_at"] is None

    # the daily rescan deletes + re-inserts the row — FBA data must come back with it
    _scan(["CVE-1", "CVE-2"])
    got = db.get_device_fba_by_name("Edge-FW-01")
    assert got["fba_state"] == "analyzed" and got["fba_findings"] == [{"issue": "x"}]

    new_id = db._connect().execute("SELECT id FROM devices").fetchone()["id"]
    db.update_device_fba(new_id, None, NOW)
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "not_found"


def test_effective_score_ignores_ruled_out_cves():
    _fresh()
    db.save_tenant_results("t1", {"tenant_name": "Acme", "devices": [{
        "resource_name": "Edge-FW-01", "os": "FortiOS 7.2.5", "platform_name": "FortiOS",
        "highest_severity_score": 9.8, "is_vulnerable": True,
        "cves": [{"id": "CVE-HI", "score": 9.8, "severity": "CRITICAL", "description": "x"},
                 {"id": "CVE-MID", "score": 6.5, "severity": "MEDIUM", "description": "x"}],
    }]})

    def scores():
        dev = db.load_tenant_results("t1")["devices"][0]
        row = next(r for r in db.get_leaderboard() if r["tenant_id"] == "t1")
        return (dev["highest_severity_score"], dev["effective_severity_score"],
                row["max_score"], row["effective_max_score"], row["effective_vulnerable_devices"])

    assert scores() == (9.8, 9.8, 9.8, 9.8, 1)            # no config → effective == raw

    db.upsert_device_config("Edge-FW-01", "push", "config a\nend", "hash-A", "fortios", 0, NOW)
    db.save_cve_verdicts("Edge-FW-01", "hash-A", [_verdict("CVE-HI", "not_applicable")], NOW)
    assert scores() == (9.8, 6.5, 9.8, 6.5, 1)            # raw CVSS untouched
    cves = {c["id"]: c["config_verdict"] for c in db.load_tenant_results("t1")["devices"][0]["cves"]}
    assert cves == {"CVE-HI": "not_applicable", "CVE-MID": None}

    db.save_cve_verdicts("Edge-FW-01", "hash-A", [_verdict("CVE-MID", "mitigated")], NOW)
    assert scores() == (9.8, 0.0, 9.8, 0.0, 0)

    # survives a rescan …
    db.save_tenant_results("t1", {"tenant_name": "Acme", "devices": [{
        "resource_name": "Edge-FW-01", "highest_severity_score": 9.8, "is_vulnerable": True,
        "cves": [{"id": "CVE-HI", "score": 9.8, "severity": "CRITICAL", "description": "x"},
                 {"id": "CVE-MID", "score": 6.5, "severity": "MEDIUM", "description": "x"}]}]})
    assert scores() == (9.8, 0.0, 9.8, 0.0, 0)

    # … but a changed config invalidates the verdicts, so the score must fall back to raw
    db.upsert_device_config("Edge-FW-01", "push", "config b\nend", "hash-B", "fortios", 0, NOW)
    assert scores() == (9.8, 9.8, 9.8, 9.8, 1)

    ranked = [r["tenant_id"] for r in db.get_leaderboard(score="effective")]
    assert "t1" in ranked


def test_reset_llm_analysis_queues_regeneration():
    _fresh()
    _scan(["CVE-1"])
    db.update_device_llm_analysis("t1", "Edge-FW-01", "old write-up")
    assert db.get_devices_needing_llm("t1") == []
    db.reset_device_llm_analysis("edge-fw-01")
    assert [d["resource_name"] for d in db.get_devices_needing_llm("t1")] == ["Edge-FW-01"]


def test_failed_lookup_overrides_stale_not_found():
    _fresh()
    _scan(["CVE-1"])
    [dev_id] = db.get_device_ids_by_name("edge-fw-01")
    db.update_device_fba(dev_id, None, NOW)                        # old code: TLS error stored as a miss
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "not_found"
    db.mark_fba_lookup_failed(dev_id, NOW)
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "lookup_failed"
    db.update_device_fba(dev_id, {"analyzed": True}, NOW)          # an answer clears the failure
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "analyzed"


def test_one_time_requeue_of_untrusted_not_found_rows():
    _fresh()
    _scan(["CVE-1"])
    [dev_id] = db.get_device_ids_by_name("Edge-FW-01")
    db.update_device_fba(dev_id, None, NOW)
    conn = db._connect()
    conn.execute("PRAGMA user_version = 0")                        # a database from before this release
    conn.commit()
    db.init_db()
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "pending"
    db.update_device_fba(dev_id, None, NOW)
    db.init_db()                                                   # runs once only
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "not_found"


def test_fba_result_change_queues_analysis_regeneration():
    _fresh()
    _scan(["CVE-1"])
    db.update_device_llm_analysis("t1", "Edge-FW-01", "written before FBA data existed")
    [dev_id] = db.get_device_ids_by_name("Edge-FW-01")

    # "not found" carries no audit → nothing to regenerate from
    assert db.update_device_fba(dev_id, None, NOW) is False
    assert db.get_devices_needing_llm("t1") == []

    audit = {"analyzed": True, "vulnerable": False, "reason": "trusthosts set",
             "findings": [{"severity": "WARNING", "category": "ACL_EXPOSURE", "issue": "loopback"}]}
    assert db.update_device_fba(dev_id, audit, NOW) is True
    assert [d["resource_name"] for d in db.get_devices_needing_llm("t1")] == ["Edge-FW-01"]

    # same audit again (daily refresh) → no churn
    db.update_device_llm_analysis("t1", "Edge-FW-01", "rewritten with FBA data")
    assert db.update_device_fba(dev_id, audit, NOW) is False
    assert db.get_devices_needing_llm("t1") == []

    # a new finding → regenerate again
    audit["findings"].append({"severity": "CRITICAL", "category": "WEAK_PASSWORD", "issue": "md5"})
    assert db.update_device_fba(dev_id, audit, NOW) is True
    assert len(db.get_devices_needing_llm("t1")) == 1


def test_fba_only_queries_fortinet_devices():
    _fresh()
    db.save_tenant_results("t1", {"tenant_name": "Acme", "devices": [
        {"resource_name": "Edge-FW-01", "platform_name": "FortiOS", "resource_type": "FortiGate-60F",
         "highest_severity_score": 9.8, "is_vulnerable": True, "cves": [{"id": "CVE-1", "score": 9.8}]},
        {"resource_name": "core-sw-01", "platform_name": "IOS-XE", "os": "IOS-XE 17.9", "resource_type": "C9300",
         "highest_severity_score": 9.8, "is_vulnerable": True, "cves": [{"id": "CVE-2", "score": 9.8}]},
        {"resource_name": "ap-lobby", "platform_name": "", "os": "", "resource_type": "FortiAP-231F",
         "highest_severity_score": 0, "is_vulnerable": False, "cves": []},
    ]})
    queued = sorted(d["resource_name"] for d in db.get_devices_needing_fba_refresh())
    assert queued == ["Edge-FW-01", "ap-lobby"]            # model alone is enough; Cisco never queued
    assert db.get_device_fba_by_name("core-sw-01")["fba_state"] == "not_applicable"
    assert db.get_device_fba_by_name("Edge-FW-01")["fba_state"] == "pending"
