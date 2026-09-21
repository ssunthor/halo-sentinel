"""Offline tests for config-aware CVE applicability (no network, no LLM).

Run from sentinel/backend:  python3 -m pytest tests/ -q
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config_sections as cs  # noqa: E402
import cve_applicability as ca  # noqa: E402

FORTIOS = """#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
#conf_file_ver=123
config system global
    set hostname "edge-fw-01"
    set admin-sport 8443
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set allowaccess ping https ssh
        config ipv6
            set ip6-allowaccess ping
        end
    next
    edit "internal"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2abcdefghijklmnop==
    next
end
config system replacemsg admin "pre_admin-disclaimer-text"
    set buffer "line one
end
still inside the banner"
end
config vpn ssl settings
    set status disable
end
config vpn ipsec phase1-interface
    edit "to-hq"
        set psksecret ENC abcdef123456
        set remote-gw 198.51.100.1
    next
end
"""

CISCO = """!
hostname core-sw-01
!
enable secret 5 $1$abcd$xyzxyzxyzxyzxyzxyz
username admin privilege 15 secret 9 $9$abcdefg
!
ip http server
no ip http secure-server
!
interface GigabitEthernet0/1
 description uplink
 ip address 192.0.2.1 255.255.255.0
!
snmp-server community s3cr3t RO
!
line vty 0 4
 access-class 10 in
 transport input ssh
!
"""

JUNOS_BRACE = """system {
    host-name edge-rtr;
    root-authentication {
        encrypted-password "$6$abc$defdefdef";
    }
    services {
        ssh;
        web-management {
            http {
                interface ge-0/0/0.0;
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.2/24;
            }
        }
    }
}
snmp {
    community public {
        authorization read-only;
    }
}
protocols {
    bgp {
        group ext {
            neighbor 192.0.2.9;
        }
    }
}
policy-options {
    policy-statement x {
        then accept;
    }
}
"""

JUNOS_SET = """set version 21.4R3
set system host-name edge-rtr
set system services ssh
set system services web-management http interface ge-0/0/0.0
set system root-authentication encrypted-password "$6$abc$defdefdef"
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/24
set snmp community public authorization read-only
"""


# ── redaction ──────────────────────────────────────────────────────────────

def test_redact_preserves_line_count_and_strips_secrets():
    for text in (FORTIOS, CISCO, JUNOS_BRACE, JUNOS_SET):
        red, n = cs.redact(text)
        assert len(red.split("\n")) == len(text.split("\n"))
        assert n > 0
    red, _ = cs.redact(FORTIOS)
    assert "SH2abcdefghijklmnop" not in red and "abcdef123456" not in red
    assert "set allowaccess ping https ssh" in red          # non-secrets untouched
    red, _ = cs.redact(CISCO)
    assert "$1$abcd" not in red and "$9$abcdefg" not in red and "s3cr3t" not in red
    assert "enable secret 5 <redacted>" in red
    red, _ = cs.redact(JUNOS_BRACE)
    assert "$6$abc" not in red


def test_redact_pem_block():
    text = 'set private-key "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\nMIIEdef\n-----END RSA PRIVATE KEY-----"\nset x y'
    red, n = cs.redact(text)
    assert "MIIEabc" not in red and "MIIEdef" not in red
    assert red.split("\n")[-1] == "set x y"
    assert n == 2


# ── parsing ────────────────────────────────────────────────────────────────

def test_fortios_sections_and_nested_end():
    style, secs = cs.parse_sections(FORTIOS)
    assert style == "fortios"
    paths = [s.path for s in secs]
    assert paths == [
        "header", "system global", "system interface", "system admin",
        'system replacemsg admin "pre_admin-disclaimer-text"',
        "vpn ssl settings", "vpn ipsec phase1-interface",
    ]
    lines = FORTIOS.split("\n")
    iface = secs[2]
    assert lines[iface.start - 1] == "config system interface"
    assert lines[iface.end - 1] == "end"
    # nested `config ipv6 ... end` must not close the section early
    assert any("internal" in l for l in lines[iface.start - 1:iface.end])
    # an "end" line inside a multi-line quoted banner must not close its section
    banner = secs[4]
    assert "still inside the banner" in "\n".join(lines[banner.start - 1:banner.end])


def test_cisco_sections():
    style, secs = cs.parse_sections(CISCO)
    assert style == "indented"
    by_path = {s.path: s for s in secs}
    vty = by_path["line vty 0 4"]
    assert len(vty) == 3
    assert "ip http server" in by_path and "no ip http secure-server" in by_path


def test_junos_styles():
    style, secs = cs.parse_sections(JUNOS_BRACE)
    assert style == "brace"
    paths = {s.path for s in secs}
    assert {"system", "system services", "snmp", "protocols bgp"} <= paths

    style, secs = cs.parse_sections(JUNOS_SET)
    assert style == "set"
    assert "system services" in {s.path for s in secs}


# ── selection ──────────────────────────────────────────────────────────────

def test_select_by_name_and_keyword():
    style, secs = cs.parse_sections(FORTIOS)
    chosen = cs.select_lines(FORTIOS, style, secs, ["config vpn ssl settings"], ["allowaccess"])
    text = cs.render_excerpt(FORTIOS, secs, chosen)
    assert "set status disable" in text          # by section name
    assert "set allowaccess ping https ssh" in text   # by keyword
    assert "remote-gw" not in text               # unrelated section left out
    assert "#config-version" in text             # header always included


def test_oversized_section_trimmed_to_matching_edit_blocks():
    body = "".join(
        f'    edit {i}\n        set name "p{i}"\n        set service "ALL"\n    next\n'
        for i in range(1, 200)
    )
    body += '    edit 999\n        set name "sslvpn-in"\n        set srcintf "ssl.root"\n    next\n'
    cfg = ("config system global\nend\nconfig system dns\nend\nconfig system ntp\nend\n"
           "config firewall policy\n" + body + "end\n")
    style, secs = cs.parse_sections(cfg)
    chosen = cs.select_lines(cfg, style, secs, ["firewall policy"], ["ssl.root"])
    assert len(chosen) <= cs.SECTION_LINE_CAP
    text = cs.render_excerpt(cfg, secs, chosen)
    assert "sslvpn-in" in text and '"p5"' not in text


def test_section_present():
    style, secs = cs.parse_sections(FORTIOS)
    lines = FORTIOS.split("\n")
    assert cs.section_present(secs, lines, "vpn ssl settings")
    assert not cs.section_present(secs, lines, "system snmp community")


# ── evidence validation ────────────────────────────────────────────────────

def _setup():
    content, _ = cs.redact(FORTIOS)
    style, secs = cs.parse_sections(content)
    shown = cs.select_lines(content, style, secs, ["vpn ssl settings", "system interface"], [])
    return content, secs, shown


def _line_of(content, needle):
    return next(i for i, l in enumerate(content.split("\n"), 1) if needle in l)


def test_valid_evidence_is_sliced_from_real_config():
    content, secs, shown = _setup()
    n = _line_of(content, "set status disable")
    raw = {"assessments": [{
        "cve_id": "CVE-2024-0001", "verdict": "not_applicable", "rationale": "SSL-VPN is disabled.",
        "evidence": [{"start_line": n - 1, "end_line": n + 1, "note": "ssl vpn off"}],
        "suggested_change": "", "change_note": "",
    }]}
    [row] = ca.validate_assessments(raw, [{"id": "CVE-2024-0001"}], content, secs, shown)
    assert row["verdict"] == "not_applicable"
    assert row["evidence"][0]["section"] == "vpn ssl settings"
    assert row["evidence"][0]["snippet"] == "config vpn ssl settings\n    set status disable\nend"


def test_risk_lowering_verdict_without_evidence_is_downgraded():
    content, secs, shown = _setup()
    hidden = _line_of(content, "set remote-gw")      # exists, but was never shown to the model
    raw = {"assessments": [
        {"cve_id": "CVE-A", "verdict": "mitigated", "rationale": "trust me",
         "evidence": [{"start_line": hidden, "end_line": hidden}],
         "suggested_change": "config x\nend"},
        {"cve_id": "CVE-B", "verdict": "not_applicable", "rationale": "out of range",
         "evidence": [{"start_line": 9000, "end_line": 9001}]},
        # claims a section is absent that is actually present
        {"cve_id": "CVE-C", "verdict": "not_applicable", "rationale": "no vpn",
         "evidence": [], "absent_sections": ["vpn ssl settings"]},
        # genuinely absent section is accepted
        {"cve_id": "CVE-D", "verdict": "not_applicable", "rationale": "no snmp",
         "evidence": [], "absent_sections": ["system snmp community"]},
    ]}
    cves = [{"id": x} for x in ("CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E")]
    rows = {r["cve_id"]: r for r in ca.validate_assessments(raw, cves, content, secs, shown)}
    assert rows["CVE-A"]["verdict"] == "undetermined" and rows["CVE-A"]["suggested_change"] == ""
    assert rows["CVE-B"]["verdict"] == "undetermined"
    assert rows["CVE-C"]["verdict"] == "undetermined"
    assert rows["CVE-D"]["verdict"] == "not_applicable"
    assert rows["CVE-D"]["absent_sections"] == ["system snmp community"]
    assert rows["CVE-E"]["verdict"] == "undetermined"      # model skipped it


def test_exploitable_keeps_verdict_and_change():
    content, secs, shown = _setup()
    n = _line_of(content, "set allowaccess ping https ssh")
    raw = {"assessments": [{
        "cve_id": "CVE-X", "verdict": "exploitable", "rationale": "HTTPS admin on WAN.",
        "evidence": [{"start_line": n, "end_line": n, "note": "wan1 admin access"}],
        "suggested_change": '```\nconfig system interface\\nedit "wan1"\\nset allowaccess ping\\nend\n```',
        "change_note": "Removes admin access from WAN.",
    }]}
    [row] = ca.validate_assessments(raw, [{"id": "CVE-X"}], content, secs, shown)
    assert row["verdict"] == "exploitable"
    assert row["suggested_change"].startswith("config system interface\nedit")
    assert "```" not in row["suggested_change"]


# ── end-to-end with a fake LLM ─────────────────────────────────────────────

class FakeLLM:
    def __init__(self, content):
        self.content = content
        self.prompts = []

    def get_chat_completion(self, messages, **kw):
        self.prompts.append(messages[0]["content"])
        n = _line_of(self.content, "set status disable")
        return {"content": json.dumps({"assessments": [{
            "cve_id": "CVE-2024-21762", "verdict": "not_applicable",
            "rationale": "SSL-VPN is disabled.",
            "evidence": [{"start_line": n, "end_line": n}],
        }]})}


def test_assess_device_end_to_end():
    content, _ = cs.redact(FORTIOS)
    llm = FakeLLM(content)
    cves = [
        {"id": "CVE-2024-21762", "score": 9.8, "description": "sslvpnd out-of-bounds write"},
        {"id": "CVE-2023-0000", "score": 7.5, "description": "kernel packet parsing"},
        {"id": "CVE-2022-9999", "score": 5.0, "description": "no requirements yet"},
    ]
    reqs = {
        "CVE-2024-21762": {"component": "SSL-VPN", "requires": "SSL-VPN enabled",
                           "config_dependent": True,
                           "config_sections": ["vpn ssl settings"], "keywords": ["ssl.root"]},
        "CVE-2023-0000": {"component": "kernel", "requires": "", "config_dependent": False,
                          "config_sections": [], "keywords": []},
    }
    rows = {r["cve_id"]: r for r in ca.assess_device(
        llm, {"resource_name": "edge-fw-01", "platform_name": "FortiOS"}, content, cves, reqs)}
    assert rows["CVE-2024-21762"]["verdict"] == "not_applicable"
    assert rows["CVE-2023-0000"]["verdict"] == "config_independent"
    assert "CVE-2022-9999" not in rows                 # retried once requirements exist
    assert len(llm.prompts) == 1
    assert "SH2abcdefghijklmnop" not in llm.prompts[0]  # secrets never reach the prompt


def test_redact_is_idempotent():
    # Halo redacts before pushing and Sentinel redacts again on receipt; the
    # stored content hash is only stable if the second pass changes nothing.
    for text in (FORTIOS, CISCO, JUNOS_BRACE, JUNOS_SET):
        once, _ = cs.redact(text)
        twice, _ = cs.redact(once)
        assert once == twice


# ── verdicts → prose analysis ──────────────────────────────────────────────

def test_verdict_fingerprint_and_prompt_block():
    cves = [{"id": "CVE-A"}, {"id": "CVE-B"}, {"id": "CVE-C"}]
    assert ca.verdict_fingerprint({}, cves) == "" and ca.verdicts_prompt_block(None, cves) == ""

    verdicts = {
        "CVE-A": {"verdict": "not_applicable", "rationale": "SSL-VPN disabled", "stale": False},
        "CVE-B": {"verdict": "exploitable", "rationale": "admin on WAN", "stale": True},   # old config
        "CVE-Z": {"verdict": "exploitable", "rationale": "other device's CVE", "stale": False},
        "CVE-C": {"verdict": "not_assessed", "rationale": "", "stale": False},
    }
    fp = ca.verdict_fingerprint(verdicts, cves)
    assert fp and fp == ca.verdict_fingerprint(dict(reversed(list(verdicts.items()))), cves)

    block = ca.verdicts_prompt_block(verdicts, cves)
    assert "CVE-A: NOT APPLICABLE" in block and "SSL-VPN disabled" in block
    assert "admin on WAN" not in block and "CVE-Z" not in block      # stale / foreign excluded
    assert "version match only): CVE-B, CVE-C" in block

    # a changed verdict must change the key, so the old write-up is not reused
    verdicts["CVE-A"] = {**verdicts["CVE-A"], "verdict": "exploitable"}
    assert ca.verdict_fingerprint(verdicts, cves) != fp
