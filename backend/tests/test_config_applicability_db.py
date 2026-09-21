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
