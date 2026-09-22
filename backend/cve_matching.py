"""Decide whether an NVD CVE actually applies to a device's software version.

Sentinel finds candidate CVEs with NVD's free-text keywordSearch ("FortiOS
7.2.13"), which returns any CVE whose text mentions those tokens. That is how a
FortiOS 7.2.13 device was matched to CVE-2024-52965, whose description lists
"7.2.13" only for FortiProxy (FortiOS was fixed in 7.2.11). NVD also ships
structured CPE version ranges with every CVE; this module uses them.

Rule (deliberately conservative — a false drop hides a real vulnerability):

  A CVE is DROPPED only when NVD lists at least one vulnerable CPE range for
  the device's own product and the device's version is outside every one of
  them. A CVE with no CPE data, or no entry for this product, is KEPT.

Stdlib only; pure functions, unit-tested.
"""

import re

# NetBox platform name (lowercased, non-alphanumerics removed) → NVD CPE product.
# Only needed where the two differ; the fallback compares the normalised names.
_PRODUCT_ALIASES = {
    "fortios": "fortios",
    "fortigate": "fortios",
    "fortinetfortios": "fortios",
    "ciscoiosxe": "ios_xe",
    "iosxe": "ios_xe",
    "ciscoios": "ios",
    "ciscoiosxr": "ios_xr",
    "iosxr": "ios_xr",
    "cisconxos": "nx_os",
    "nxos": "nx_os",
    "ciscoasa": "adaptive_security_appliance_software",
    "asa": "adaptive_security_appliance_software",
    "junos": "junos",
    "juniperjunos": "junos",
    "junosos": "junos",
    "panos": "pan-os",
    "paloaltopanos": "pan-os",
    "aristaeos": "eos",
    "eos": "eos",
}


def _squash(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def device_product(os_name: str) -> str | None:
    """CPE product token for a NetBox platform name, or None if unknown."""
    key = _squash(os_name)
    if not key:
        return None
    if key in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[key]
    # "FortiOS 7.4" style platform names carry a version; strip it
    key_nodigits = re.sub(r"\d.*$", "", key)
    if key_nodigits in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[key_nodigits]
    return key_nodigits or key


def _product_matches(cpe_product: str, product: str) -> bool:
    return _squash(cpe_product) == _squash(product)


def version_key(v: str) -> tuple:
    """'7.2.13' → (7, 2, 13); '17.9.4a' → (17, 9, 4). Empty → ()."""
    parts = []
    for seg in re.split(r"[.\-_]", v or ""):
        m = re.match(r"^(\d+)", seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts)


def device_version(os_version: str) -> str | None:
    """The dotted numeric version in a NetBox os_version/os_build string:
    'v7.2.13,build1762,260128 (GA.M)' → '7.2.13'."""
    m = re.search(r"(\d+(?:\.\d+)+)", str(os_version or ""))
    return m.group(1) if m else None


def _cmp(a: tuple, b: tuple) -> int:
    """Compare version tuples, padding the shorter with zeros so (7,2) == (7,2,0)."""
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _entry_covers(entry: dict, ver: tuple) -> bool:
    """Does one vulnerable cpeMatch entry include this version?"""
    criteria = entry.get("criteria") or ""
    fields = criteria.split(":")
    cpe_version = fields[5] if len(fields) > 5 else "*"
    lo_inc, lo_exc = entry.get("versionStartIncluding"), entry.get("versionStartExcluding")
    hi_inc, hi_exc = entry.get("versionEndIncluding"), entry.get("versionEndExcluding")
    if not any((lo_inc, lo_exc, hi_inc, hi_exc)):
        if cpe_version in ("*", "-", ""):
            return True                          # "all versions"
        return _cmp(version_key(cpe_version), ver) == 0
    if lo_inc and _cmp(ver, version_key(lo_inc)) < 0:
        return False
    if lo_exc and _cmp(ver, version_key(lo_exc)) <= 0:
        return False
    if hi_inc and _cmp(ver, version_key(hi_inc)) > 0:
        return False
    if hi_exc and _cmp(ver, version_key(hi_exc)) >= 0:
        return False
    return True


def product_entries(cve: dict, product: str) -> list[dict]:
    """Vulnerable cpeMatch entries for this product across all configurations."""
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                fields = (m.get("criteria") or "").split(":")
                if len(fields) > 4 and _product_matches(fields[4], product):
                    out.append(m)
    return out


def cve_applies(cve: dict, product: str | None, version: str | None) -> bool:
    """False only when NVD's CPE data for this product excludes this version."""
    if not product or not version:
        return True
    entries = product_entries(cve, product)
    if not entries:
        return True                              # no data for this product — keep
    ver = version_key(version)
    if not ver:
        return True
    return any(_entry_covers(e, ver) for e in entries)


def filter_by_version(cves_data: dict, os_name: str, os_version: str) -> tuple[dict, list[str]]:
    """Return (filtered NVD response, dropped CVE ids)."""
    product, version = device_product(os_name), device_version(os_version)
    kept, dropped = [], []
    for item in cves_data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        if cve_applies(cve, product, version):
            kept.append(item)
        else:
            dropped.append(cve.get("id") or "?")
    return {**cves_data, "vulnerabilities": kept}, dropped


def recommended_version(cves_data: dict, os_name: str, os_version: str) -> str | None:
    """Lowest version of the DEVICE'S product and release branch that closes
    every remaining CVE: the highest versionEndExcluding/Including among entries
    for that product, preferring the device's major.minor branch. Falls back to
    product-wide, then to any product, when nothing narrower exists."""
    product, version = device_product(os_name), device_version(os_version)
    branch = version_key(version)[:2] if version else ()

    def fixes(entries):
        out = []
        for e in entries:
            v = e.get("versionEndExcluding") or e.get("versionEndIncluding")
            if v and v.strip():
                out.append(v.strip())
        return out

    all_entries, prod_entries = [], []
    for item in cves_data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        for cfg in cve.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    if m.get("vulnerable"):
                        all_entries.append(m)
        if product:
            prod_entries += product_entries(cve, product)

    prod_fixes = fixes(prod_entries)
    branch_fixes = [v for v in prod_fixes if version_key(v)[:2] == branch] if branch else []
    for cands in (branch_fixes, prod_fixes, fixes(all_entries)):
        if cands:
            return max(cands, key=version_key)
    return None
