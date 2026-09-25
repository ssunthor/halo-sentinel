"""GTT Engineering recommended versions via GIA/DIU (offline).

Fixtures are the real rows returned by
GET /api/sam/diu/tables/6848998_SEC_42_TABLE_1 (live table, Sept 2026) and
…TABLE_2 (the older table on the same Confluence chunk), trimmed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gia_client as gc  # noqa: E402

LIVE_HEADERS = ["Component", "Current Used Versions", "New Deployments", "GTT Preferred Version",
                "Approved Date", "PV End of Support", "Future Release*"]
LIVE_ROWS = [
    {"Component": "FortiManager (Physical or VM)", "Current Used Versions": "7.2.8", "New Deployments": "7.4.10",
     "GTT Preferred Version": "7.4.10", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.11"},
    {"Component": "FortiAnalyzer (Physical or VM)", "Current Used Versions": "7.2.8", "New Deployments": "7.4.10",
     "GTT Preferred Version": "7.4.10", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.11"},
    {"Component": "Fortigate SD WAN Edge", "Current Used Versions": "6.2.4, 6.4.7, 6.4.15, 7.2.4", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.12"},
    {"Component": "Fortigate SD WAN Edge (VM)", "Current Used Versions": "7.2.10", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.12"},
    {"Component": "Fortigate SD WAN Gateway", "Current Used Versions": "7.2.4", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.12"},
    {"Component": "Fortigate SSE Node", "Current Used Versions": "7.2.7, 7.4.8", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.12"},
    {"Component": "Fortigate VM on NFV POD", "Current Used Versions": "N/A", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "11.15.2027", "Future Release*": "7.4.12"},
    {"Component": "Fortigate Edge (non SDWAN/ipsec) F series", "Current Used Versions": "6.4.7, 6.4.15", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "4.11.2028", "Future Release*": "7.4.12"},
    {"Component": "Fortigate Edge (non SDWAN/ipsec) E Series", "Current Used Versions": "6.2.4, 6.4.7, 6.4.15", "New Deployments": "7.4.11",
     "GTT Preferred Version": "7.4.11", "Approved Date": "4.8.2026", "PV End of Support": "4.11.2028", "Future Release*": "7.4.12"},
    {"Component": "FortiSwitch (FortiLink)", "Current Used Versions": "6.4.13, 7.2.9, 7.2.10", "New Deployments": "7.4.7",
     "GTT Preferred Version": "7.4.7", "Approved Date": "2.1.2026", "PV End of Support": "12.2.2027", "Future Release*": "GTT PV"},
    {"Component": "FortiAP 221E (FortiLink)FortiAP 231F (FortiLink)FortiAP 431F (FortiLink)FortiAP 433F (FortiLink)FortiAP 231K (FortiLink)",
     "Current Used Versions": "6.4.9, 7.2.2", "New Deployments": "7.4.57.4.67.4.67.4.67.4.6",
     "GTT Preferred Version": "7.4.57.4.67.4.67.4.67.4.6", "Approved Date": "2.1.2026", "PV End of Support": "12.01.2027", "Future Release*": "GTT PV"},
    {"Component": "FortiSwitch (Used as a Nid for monitoring)", "Current Used Versions": "6.0.x, 6.2.x, 6.4.x, 7.2.9, 7.2.10", "New Deployments": "7.2.10",
     "GTT Preferred Version": "7.2.10", "Approved Date": "4.1.2025", "PV End of Support": "10.13.2026", "Future Release*": "7.4.7"},
]
OLD_HEADERS = ["Component", "Current versions", "New Deployments", "End of Support"]
OLD_ROWS = [
    {"Component": "Fortinet Forti Manager", "Current versions": "5.6.11, 6.2.8, 6.4.7, 7.2.2,7.2.4", "New Deployments": "6.4.7", "End of Support": "N/A"},
    {"Component": "Fortigate SD WAN Edge", "Current versions": "6.2.4, 6.4.7", "New Deployments": "6.4.12", "End of Support": "N/A"},
    {"Component": "Fortigate Edge (non SDWAN) F series", "Current versions": "6.2.4, 6.4.7", "New Deployments": "6.4.12, 7.2.4", "End of Support": "N/A"},
]


def _search_body(as_string: bool = False):
    tables = {"6848998_SEC_42_TABLE_2": {"headers": OLD_HEADERS, "rows": OLD_ROWS},
              "6848998_SEC_42_TABLE_1": {"headers": LIVE_HEADERS, "rows": LIVE_ROWS}}
    return {"pages": [{"metadata": {"title": "SD-WAN Software Version Control"}, "chunks": [
        {"header_text": "Fortinet Edges, Gateways, and Central Management Devices", "raw_text_content": ""},
        {"header_text": "Approved versions",
         "structured_tables_json": json.dumps(tables) if as_string else tables},
    ]}]}


def _live_table():
    return gc.pick_table(gc.tables_from_search(_search_body()))


# --- table discovery ---------------------------------------------------------

def test_search_yields_both_tables_and_picks_the_live_one():
    tables = gc.tables_from_search(_search_body())
    assert sorted(t["table_id"] for t in tables) == ["6848998_SEC_42_TABLE_1", "6848998_SEC_42_TABLE_2"]
    live = gc.pick_table(tables)
    assert live["table_id"] == "6848998_SEC_42_TABLE_1"
    assert live["chunk_header"] == "Approved versions"
    assert live["page_title"] == "SD-WAN Software Version Control"


def test_structured_tables_json_may_be_a_json_string():
    assert gc.pick_table(gc.tables_from_search(_search_body(as_string=True)))["table_id"] == "6848998_SEC_42_TABLE_1"


def test_table_lookup_response_is_parsed():
    body = {"table_id": "6848998_SEC_42_TABLE_1", "page_title": "SD-WAN Software Version Control",
            "chunk_header_text": "Approved versions",
            "table_data_json": {"headers": LIVE_HEADERS, "rows": LIVE_ROWS}}
    t = gc.table_from_lookup(body)
    assert t["source"] == "table_id" and len(t["parsed"]) == 16   # 12 rows, FortiAP split into 5


def test_old_table_alone_is_still_usable():
    body = {"table_id": "6848998_SEC_42_TABLE_2", "table_data_json": {"headers": OLD_HEADERS, "rows": OLD_ROWS}}
    t = gc.table_from_lookup(body)
    rec = gc.recommend("FortiOS", "v6.4.7,build1911", "FortiGate-60F", "CPE", "device", table=t)
    assert rec["gia_recommended_version"] == "6.4.12" and rec["gia_upgrade_needed"]


def test_pick_table_with_nothing():
    assert gc.pick_table([]) is None
    assert gc.tables_from_search({"pages": []}) == []
    assert gc.table_from_lookup({"table_id": "x", "table_data_json": {"rows": []}}) is None


# --- row parsing -------------------------------------------------------------

def test_merged_fortiap_row_is_split_back_into_models():
    rows = {r["component"]: r for r in _live_table()["parsed"]}
    assert rows["FortiAP 221E (FortiLink)"]["preferred_version"] == "7.4.5"
    assert rows["FortiAP 231F (FortiLink)"]["preferred_version"] == "7.4.6"
    assert rows["FortiAP 231K (FortiLink)"]["preferred_version"] == "7.4.6"


def test_preferred_falls_back_to_new_deployments_and_takes_highest():
    [row] = gc.parse_rows([OLD_ROWS[2]])
    assert row["preferred_version"] == "7.2.4"
    assert row["end_of_support"] == "N/A" and row["approved"] == ()


def test_approved_date_is_sortable():
    assert gc._parse_date("4.8.2026") == (2026, 4, 8)
    assert gc._parse_date("11.15.2027") < gc._parse_date("4.11.2028")
    assert gc._parse_date("GTT PV") == ()


# --- device classification ---------------------------------------------------

def _component(platform, os_version, model=None, role=None, category="device"):
    rec = gc.recommend(platform, os_version, model, role, category, table=_live_table())
    return rec and rec["gia_component"]


def test_physical_fortigate_cpe_is_an_sdwan_edge():
    assert _component("FortiOS", "v7.2.13,build1762,260128 (GA.M)", "FortiGate-60F", "CPE") == "Fortigate SD WAN Edge"
    assert _component("FortiOS", "v7.2.13", "FortiGate-40F-3G4G", "CPE") == "Fortigate SD WAN Edge"
    assert _component("FortiOS", "v5.4.8", "FortiWiFi-60E", "CPE") == "Fortigate SD WAN Edge"
    assert _component("FortiOS", "v7.2.13", "Unknown", "CPE") == "Fortigate SD WAN Edge"


def test_hardware_series_is_the_fallback_when_no_sdwan_row_exists():
    table = gc.pick_table(gc.tables_from_search(_search_body()))
    table["parsed"] = [r for r in table["parsed"] if r["component"] != "Fortigate SD WAN Edge"]
    f = gc.recommend("FortiOS", "v6.4.7", "FortiGate-100F", "CPE", "device", table=table)
    e = gc.recommend("FortiOS", "v6.4.7", "FortiGate-100E", "CPE", "device", table=table)
    assert f["gia_component"] == "Fortigate Edge (non SDWAN/ipsec) F series"
    assert e["gia_component"] == "Fortigate Edge (non SDWAN/ipsec) E Series"


def test_virtual_fortigates():
    assert _component("FortiOS", "v7.2.4", "FortiGate-VM64", "CPE") == "Fortigate SD WAN Edge (VM)"
    assert _component("FortiOS", "v7.2.10", "FortiGate-VM64-KVM", "CPE") == "Fortigate SD WAN Edge (VM)"
    assert _component("FortiOS", "v7.2.10", "FortiGate-VM64-AZURE", "CPE") == "Fortigate SD WAN Edge (VM)"
    assert _component("FortiGate 6.x", "6.4.7", "nfv-cluster", "NFV Fortigate", "vm") == "Fortigate VM on NFV POD"


def test_roles_pick_gateway_and_sse_rows():
    assert _component("FortiOS", "v7.2.4", "FortiGate-VM64", "Fortinet Central Gateway") == "Fortigate SD WAN Gateway"
    assert _component("FortiOS", "v7.2.4", "FortiGate-VM64", "GW") == "Fortigate SD WAN Gateway"
    assert _component("FortiOS", "v7.4.8", "FortiGate-VM64", "SSE Node") == "Fortigate SSE Node"


def test_switches_managers_analyzers():
    assert _component("FortiOS", "v7.2.9,build0517", "FortiSwitch-108F", "CPE") == "FortiSwitch (FortiLink)"
    assert _component("FortiOS", "v7.2.9", "FortiSwitch 124E", "Switch UnSorted") == "FortiSwitch (FortiLink)"
    assert _component("FortiOS", "v7.2.9", "FortiSwitch-108F", "NID monitoring") == "FortiSwitch (Used as a Nid for monitoring)"
    assert _component("FortiManager 6.x", "6.4.7", "vm-cluster", "FortiManager", "vm") == "FortiManager (Physical or VM)"
    assert _component("FortiAnalyzer 6.x", "6.4.7", "vm-cluster", "Server UnSorted", "vm") == "FortiAnalyzer (Physical or VM)"
    assert _component("FortiOS", "7.2.2", "FortiAP-231F", "Wireless") == "FortiAP 231F (FortiLink)"


def test_non_fortinet_and_unlisted_products_get_nothing():
    assert gc.classify_device("PanOS 10.x", "PA-220", "CPE") == []
    assert gc.classify_device("JUNOS", "SRX300", "Router UnSorted") == []
    assert gc.classify_device(None, None, None) == []
    assert gc.classify_device("Windows", "VM", "FortiClient EMS") == []
    assert _component("FortiOS", "7.2.2", "FortiClient EMS", "Server") is None


# --- version comparison ------------------------------------------------------

def _rec(os_version, model="FortiGate-60F"):
    return gc.recommend("FortiOS", os_version, model, "CPE", "device", table=_live_table())


def test_device_behind_the_standard_needs_an_upgrade():
    rec = _rec("v7.2.13,build1762,260128 (GA.M)")
    assert rec["gia_upgrade_needed"] and rec["gia_recommended_version"] == "7.4.11"
    assert rec["gia_device_version"] == "7.2.13"
    assert gc.upgrade_fields(rec) == {"gia_recommended_version": "7.4.11", "gia_component": "Fortigate SD WAN Edge"}


def test_device_on_or_past_the_standard_is_compliant():
    assert _rec("v7.4.11,build2878,260126 (GA.M)")["gia_upgrade_needed"] is False
    assert _rec("v7.4.12,build2902,260505 (GA.M)")["gia_upgrade_needed"] is False
    assert _rec("v7.6.7,build3704")["gia_upgrade_needed"] is False
    assert gc.upgrade_fields(_rec("v7.4.11")) == {"gia_recommended_version": None, "gia_component": None}
    assert gc.upgrade_fields(None) == {"gia_recommended_version": None, "gia_component": None}


def test_unknown_device_version_is_treated_as_needing_the_upgrade():
    rec = _rec(None)
    assert rec["gia_upgrade_needed"] and rec["gia_device_version"] is None
    assert _rec("")["gia_upgrade_needed"]


def test_switch_versions_compare_against_the_switch_row():
    assert _rec("v7.2.9,build0517", "FortiSwitch-108F")["gia_recommended_version"] == "7.4.7"
    assert _rec("v7.4.7,build0914", "FortiSwitch-108F")["gia_upgrade_needed"] is False


def test_netbox_dict_extraction():
    dev = {"platform": {"name": "FortiOS"}, "device_type": {"model": "FortiGate-60F"},
           "role": {"name": "CPE"}, "custom_fields": {"os_build": "v7.2.13,build1762"}}
    assert gc.netbox_fields(dev, "device") == {"platform": "FortiOS", "os_version": "v7.2.13,build1762",
                                               "model": "FortiGate-60F", "role": "CPE", "category": "device"}
    vm = {"platform": {"name": "FortiManager 6.x"}, "cluster": {"name": "NFV-POD-1"},
          "device_role": {"name": "FortiManager"}, "custom_fields": {"os_version": "7.2.8"}}
    assert gc.netbox_fields(vm, "vm")["model"] == "NFV-POD-1" and gc.netbox_fields(vm, "vm")["role"] == "FortiManager"
    assert gc.netbox_fields({}, "device") == {"platform": None, "os_version": None, "model": None,
                                              "role": None, "category": "device"}
