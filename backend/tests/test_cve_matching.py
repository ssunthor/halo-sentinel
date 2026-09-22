"""Version-range filtering of NVD keyword-search results (offline)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cve_matching as cm  # noqa: E402


def _cpe(product, lo=None, hi=None, exact=None):
    e = {"vulnerable": True, "criteria": f"cpe:2.3:o:fortinet:{product}:{exact or '*'}:*:*:*:*:*:*:*"}
    if lo: e["versionStartIncluding"] = lo
    if hi: e["versionEndExcluding"] = hi
    return e


# CVE-2024-52965 exactly as NVD publishes it: FortiOS fixed in 7.2.11, FortiProxy in 7.2.14
CVE_52965 = {"id": "CVE-2024-52965", "configurations": [{"nodes": [{"cpeMatch": [
    _cpe("fortiproxy", "7.0.0", "7.0.21"), _cpe("fortiproxy", "7.2.0", "7.2.14"),
    _cpe("fortiproxy", "7.4.0", "7.4.9"), _cpe("fortiproxy", "7.6.0", "7.6.2"),
    _cpe("fortios", "7.0.1", "7.0.17"), _cpe("fortios", "7.2.0", "7.2.11"),
    _cpe("fortios", "7.4.0", "7.4.6"), _cpe("fortios", exact="7.6.0"), _cpe("fortios", exact="7.6.1"),
]}]}]}


def test_fortios_7_2_13_is_not_affected_by_cve_2024_52965():
    assert cm.cve_applies(CVE_52965, "fortios", "7.2.13") is False
    assert cm.cve_applies(CVE_52965, "fortios", "7.2.10") is True
    assert cm.cve_applies(CVE_52965, "fortios", "7.2.11") is False
    assert cm.cve_applies(CVE_52965, "fortios", "7.6.1") is True      # exact-version CPE
    assert cm.cve_applies(CVE_52965, "fortios", "7.6.2") is False
    assert cm.cve_applies(CVE_52965, "fortiproxy", "7.2.13") is True  # the range the text mentions


def test_conservative_when_no_data():
    assert cm.cve_applies({"id": "X"}, "fortios", "7.2.13") is True                       # no CPE data
    assert cm.cve_applies(CVE_52965, "junos", "21.4") is True                              # other product only
    assert cm.cve_applies(CVE_52965, None, "7.2.13") is True and cm.cve_applies(CVE_52965, "fortios", None) is True
    wildcard = {"configurations": [{"nodes": [{"cpeMatch": [_cpe("fortios")]}]}]}
    assert cm.cve_applies(wildcard, "fortios", "7.2.13") is True                           # "all versions"


def test_netbox_strings_and_products():
    assert cm.device_version("v7.2.13,build1762,260128 (GA.M)") == "7.2.13"
    assert cm.device_version("17.9.4a") == "17.9.4" and cm.device_version("garbage") is None
    assert cm.device_product("FortiOS") == "fortios" and cm.device_product("FortiOS 7.4") == "fortios"
    assert cm.device_product("Cisco IOS-XE") == "ios_xe" and cm.device_product("PAN-OS") == "pan-os"
    assert cm.device_product("") is None


def test_filter_and_recommended_version():
    other = {"id": "CVE-OTHER", "configurations": [{"nodes": [{"cpeMatch": [_cpe("fortios", "7.2.0", "7.2.14")]}]}]}
    data = {"vulnerabilities": [{"cve": CVE_52965}, {"cve": other}, {"cve": {"id": "CVE-NODATA"}}]}
    kept, dropped = cm.filter_by_version(data, "FortiOS", "v7.2.13,build1762")
    assert dropped == ["CVE-2024-52965"]
    assert [v["cve"]["id"] for v in kept["vulnerabilities"]] == ["CVE-OTHER", "CVE-NODATA"]
    # min fix comes from the device's product and branch — not FortiProxy's 7.6.2
    assert cm.recommended_version(kept, "FortiOS", "7.2.13") == "7.2.14"
    assert cm.recommended_version(data, "FortiOS", "7.2.13") == "7.2.14"
    assert cm.recommended_version(data, "FortiOS", "7.4.2") == "7.4.6"
    assert cm.recommended_version({"vulnerabilities": [{"cve": {"id": "X"}}]}, "FortiOS", "7.2.13") is None
