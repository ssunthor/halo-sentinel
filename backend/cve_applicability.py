"""Config-aware CVE applicability: is this CVE actually exploitable on THIS
device, given its running configuration? (stdlib only — the LLM client is
passed in, so this is testable offline.)

A version match only says a device *might* be vulnerable. This module checks
the device's config for whether the vulnerable feature is enabled/exposed,
whether a compensating control is already in place, and what config change
would reduce exposure.

Two LLM stages with a deterministic step between and after them:

  1. cve_requirements()  — per CVE, text-only: what feature must be enabled,
                           which config sections/keywords to look at. Cached
                           per (cve_id, platform) by the caller; runs once for
                           the whole estate.
  2. (deterministic)     — config_sections.select_lines() pulls just those
                           sections out of the redacted config.
  3. assess_batch()      — per device, batched CVEs: verdict + rationale +
                           evidence as LINE RANGES + suggested CLI change.
  4. (deterministic)     — validate_assessments(): evidence must point at lines
                           the model was actually shown; snippets are sliced
                           from the real config; a verdict that lowers risk
                           (mitigated / not_applicable) without verifiable
                           support is downgraded to undetermined.

Verdicts:
  exploitable         vulnerable feature is enabled/exposed in the config
  mitigated           feature enabled, but config already restricts exposure
  not_applicable      vulnerable feature is not enabled on this device
  config_independent  exploitability does not depend on configuration — patch
  undetermined        config does not settle it (or evidence failed validation)
"""

import hashlib
import json
import re

import config_sections as cs

VERDICTS = ("exploitable", "mitigated", "not_applicable", "config_independent", "undetermined")
RISK_LOWERING = ("mitigated", "not_applicable")

MAX_EVIDENCE_LINES = 40
MAX_EVIDENCE_ITEMS = 4
MAX_CHANGE_CHARS = 2000
REQUIREMENTS_BATCH = 8
ASSESS_BATCH = 6

_STYLE_NOTES = {
    "fortios": "FortiOS CLI (config/edit/set/next/end). `show` output omits settings left at their default.",
    "set": "flat `set ...` commands (Junos or PAN-OS set format).",
    "brace": "Junos curly-brace hierarchy.",
    "indented": "Cisco/Arista-style running-config (column-0 command owns the indented lines below it).",
}


_VERDICT_LABELS = {
    "exploitable": "EXPLOITABLE (vulnerable feature enabled and reachable)",
    "mitigated": "MITIGATED BY CONFIG (feature enabled, access already restricted)",
    "not_applicable": "NOT APPLICABLE (vulnerable feature not enabled on this device)",
    "config_independent": "CONFIG-INDEPENDENT (no config change helps — patch)",
    "undetermined": "UNDETERMINED (config does not settle it — treat as applicable)",
}


def current_verdicts(verdicts: dict[str, dict] | None, cves: list[dict]) -> dict[str, dict]:
    """The subset of stored verdicts that may be relied on for these CVEs:
    real verdicts, computed against the device's CURRENT config."""
    ids = {c["id"] for c in cves}
    return {
        cid: v for cid, v in (verdicts or {}).items()
        if cid in ids and not v.get("stale") and v.get("verdict") in _VERDICT_LABELS
    }


def verdict_fingerprint(verdicts: dict[str, dict] | None, cves: list[dict]) -> str:
    """Short stable digest of a device's current verdicts ('' when it has none).
    Part of the prose-analysis cache key, so a write-up generated before the
    verdicts existed (or under different ones) is never reused."""
    cur = current_verdicts(verdicts, cves)
    if not cur:
        return ""
    joined = "|".join(f"{cid}:{cur[cid]['verdict']}" for cid in sorted(cur))
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def verdicts_prompt_block(verdicts: dict[str, dict] | None, cves: list[dict]) -> str:
    """Prompt section that makes the prose risk write-up agree with the per-CVE
    config verdicts shown beside it in the UI."""
    cur = current_verdicts(verdicts, cves)
    if not cur:
        return ""
    lines = "\n".join(
        f"- {cid}: {_VERDICT_LABELS[v['verdict']]} — {(v.get('rationale') or '')[:400]}"
        for cid, v in sorted(cur.items())
    )
    unassessed = sorted({c["id"] for c in cves} - set(cur))
    rest = (f"\nNot assessed against the config (version match only): {', '.join(unassessed[:20])}"
            if unassessed else "")
    return (
        "\n\nCONFIG-VERIFIED APPLICABILITY (each verdict was checked against this device's "
        "actual running configuration and is shown to the user next to your write-up):\n"
        f"{lines}{rest}\n\n"
        "Treat these verdicts as established facts and stay consistent with them:\n"
        "- Lead with EXPLOITABLE CVEs — they are the urgent ones.\n"
        "- For NOT APPLICABLE or MITIGATED CVEs, say the software version is affected but the "
        "device's configuration currently rules out or limits exploitation, and why. Do NOT call "
        "them critical, urgent or actively exploitable. Note the protection lasts only while the "
        "configuration stays that way, so they still belong in the next planned upgrade.\n"
        "- Base the overall urgency on the CVEs that remain exploitable, config-independent or "
        "undetermined — not on the raw CVSS of CVEs the configuration has ruled out."
    )


def _loads(text: str):
    """Parse an LLM JSON reply, tolerating code fences and leading prose."""
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def _chat_json(llm, prompt: str, max_tokens: int):
    messages = [{"role": "user", "content": prompt}]
    resp = llm.get_chat_completion(messages, temperature=0.0, json_mode=True, max_tokens=max_tokens)
    if not resp or not resp.get("content"):
        return None
    return _loads(resp["content"])


# ---------------------------------------------------------------------------
# Stage 1 — what does each CVE need in order to be exploitable?
# ---------------------------------------------------------------------------

def cve_requirements(llm, platform: str, cves: list[dict]) -> dict[str, dict]:
    """Return {cve_id: requirements} for up to REQUIREMENTS_BATCH CVEs.

    requirements = {component, requires, config_dependent, config_sections, keywords}
    CVEs the model skipped are absent from the result (caller retries later).
    """
    cve_block = "\n".join(f"- {c['id']}: {c.get('description') or ''}"[:1200] for c in cves)
    prompt = (
        f"You are a network security engineer. Platform: {platform or 'unknown'}.\n\n"
        "For each CVE below, state what must be true of a device's CONFIGURATION for the "
        "vulnerability to be reachable, and where in the device's configuration that would "
        "be visible.\n\n"
        f"{cve_block}\n\n"
        "Reply with one JSON object keyed by CVE ID. Each value:\n"
        "{\n"
        '  "component": "affected feature/daemon, e.g. SSL-VPN web portal",\n'
        '  "requires": "one sentence: the feature/exposure that must be enabled for exploitation",\n'
        '  "config_dependent": true|false,\n'
        '  "config_sections": ["config section names in THIS platform\'s syntax that show whether '
        'the feature is enabled or restricted, e.g. \\"vpn ssl settings\\", \\"system interface\\", '
        '\\"firewall local-in-policy\\", \\"line vty\\", \\"ip http\\""],\n'
        '  "keywords": ["literal config tokens to search for, e.g. \\"allowaccess\\", \\"trusthost\\""]\n'
        "}\n"
        "Set config_dependent=false only when exploitability genuinely does not depend on any "
        "configurable feature or exposure (e.g. a flaw in core packet processing that is always "
        "on). When unsure, use true. Include sections for both the feature itself and the "
        "controls that could restrict access to it (management access lists, trusted hosts, "
        "local-in policies, interface access settings). At most 6 sections and 8 keywords per CVE."
    )
    data = _chat_json(llm, prompt, max_tokens=2500)
    if not isinstance(data, dict):
        return {}
    wanted = {c["id"] for c in cves}
    out = {}
    for cve_id, req in data.items():
        if cve_id not in wanted or not isinstance(req, dict):
            continue
        out[cve_id] = {
            "component": str(req.get("component") or "")[:200],
            "requires": str(req.get("requires") or "")[:500],
            "config_dependent": req.get("config_dependent") is not False,
            "config_sections": [str(s)[:80] for s in (req.get("config_sections") or [])][:6],
            "keywords": [str(k)[:40] for k in (req.get("keywords") or [])][:8],
        }
    return out


# ---------------------------------------------------------------------------
# Stage 3 — assess a batch of CVEs against the selected config lines
# ---------------------------------------------------------------------------

def build_assessment_prompt(
    device: dict,
    style: str,
    index: list[str],
    excerpt: str,
    cves: list[dict],
    requirements: dict[str, dict],
    fba_findings: list[dict] | None = None,
) -> str:
    cve_lines = []
    for c in cves:
        req = requirements.get(c["id"], {})
        cve_lines.append(
            f"- {c['id']} (CVSS {c.get('score')}): {(c.get('description') or '')[:600]}\n"
            f"  Needs: {req.get('requires') or 'unknown'}"
        )
    fba_block = ""
    if fba_findings:
        fba_block = "\nIndependent config-audit findings for this device (context only):\n" + "\n".join(
            f"- [{f.get('severity', '?')}] {f.get('category', '')}: {f.get('issue', '')}"[:400]
            for f in fba_findings[:8]
        ) + "\n"

    return (
        "You are a network security engineer deciding whether known CVEs are actually "
        "exploitable on one specific device, based on its running configuration.\n\n"
        f"Device: {device.get('resource_name')} | Platform: {device.get('platform_name') or ''} "
        f"| OS: {device.get('os') or ''} | Model: {device.get('resource_type') or ''}\n"
        f"Config syntax: {_STYLE_NOTES.get(style, style)}\n\n"
        "All top-level sections present in the full config:\n"
        f"{', '.join(index)}\n\n"
        "Relevant config excerpt. Each line is prefixed with its REAL line number; `...` marks "
        "skipped lines. Secrets are replaced with <redacted>.\n"
        "```\n"
        f"{excerpt}\n"
        "```\n"
        f"{fba_block}\n"
        "CVEs matched to this device by software version:\n"
        + "\n".join(cve_lines) + "\n\n"
        "For EACH CVE decide a verdict:\n"
        "- exploitable: the config shows the vulnerable feature enabled and reachable.\n"
        "- mitigated: the feature is enabled, but the config already restricts who can reach it "
        "(trusted hosts, management ACL, local-in policy, interface access limits, feature-level "
        "restriction). Cite the restricting lines.\n"
        "- not_applicable: the vulnerable feature is not enabled on this device. Either cite the "
        "lines that disable it, or list its section in absent_sections IF that section is missing "
        "from the section list above AND the platform default for the feature is disabled.\n"
        "- config_independent: exploitability does not depend on configuration.\n"
        "- undetermined: the excerpt does not settle it. Prefer this over guessing — a wrong "
        "not_applicable hides a real vulnerability.\n\n"
        "Rules:\n"
        "- Use ONLY the excerpt and section list. Never invent configuration.\n"
        "- Evidence is cited by line numbers copied from the excerpt prefixes, never by quoting "
        "text. Keep each range tight (the specific lines that prove the point, max 25 lines).\n"
        "- suggested_change: ready-to-paste CLI in this device's syntax that removes or reduces "
        "exposure to this CVE (disable the unused feature, restrict access to trusted "
        "sources, etc). Use placeholders like <MGMT_SUBNET> for values you cannot know. Give one "
        "for exploitable verdicts whenever a config workaround exists, and for mitigated verdicts "
        "only if the mitigation can be tightened. Empty string if no config change helps. "
        "Upgrading firmware is always the real fix — do not put upgrade steps here.\n\n"
        "Reply with JSON only:\n"
        '{"assessments": [{\n'
        '  "cve_id": "CVE-...",\n'
        '  "verdict": "exploitable|mitigated|not_applicable|config_independent|undetermined",\n'
        '  "rationale": "2-3 sentences tying the verdict to the cited config",\n'
        '  "evidence": [{"start_line": 0, "end_line": 0, "note": "what these lines show"}],\n'
        '  "absent_sections": ["section names that are absent and prove the feature is off"],\n'
        '  "suggested_change": "CLI or empty string",\n'
        '  "change_note": "one sentence on what the change does and any side effect"\n'
        "}]}"
    )


def _clean_change(text) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text.strip())
    return text.replace("\\n", "\n").strip()[:MAX_CHANGE_CHARS]


def validate_assessments(
    raw: dict | None,
    cves: list[dict],
    content: str,
    sections: list[cs.Section],
    shown: set[int],
) -> list[dict]:
    """Turn the model's reply into trustworthy rows — one per CVE in `cves`.

    - evidence ranges must lie entirely inside lines the model was shown
    - snippets are sliced from the real (redacted) config, never model-quoted
    - absent_sections are re-checked against the full config
    - mitigated / not_applicable without surviving support → undetermined
    """
    lines = content.split("\n")
    by_id = {}
    for a in (raw or {}).get("assessments") or []:
        if isinstance(a, dict) and a.get("cve_id"):
            by_id.setdefault(str(a["cve_id"]), a)

    results = []
    for c in cves:
        a = by_id.get(c["id"])
        if not a:
            results.append(_row(c["id"], "undetermined", "The model returned no assessment for this CVE."))
            continue

        verdict = str(a.get("verdict") or "").strip().lower()
        if verdict not in VERDICTS:
            verdict = "undetermined"
        rationale = str(a.get("rationale") or "").strip()[:1500]

        evidence = []
        for ev in (a.get("evidence") or [])[:MAX_EVIDENCE_ITEMS]:
            try:
                start, end = int(ev.get("start_line")), int(ev.get("end_line"))
            except (TypeError, ValueError, AttributeError):
                continue
            if start > end:
                start, end = end, start
            if start < 1 or end > len(lines):
                continue
            end = min(end, start + MAX_EVIDENCE_LINES - 1)
            if not all(i in shown for i in range(start, end + 1)):
                continue
            evidence.append({
                "section": cs.enclosing_section(sections, start, end),
                "start_line": start,
                "end_line": end,
                "snippet": cs.slice_lines(content, start, end),
                "note": str(ev.get("note") or "")[:300],
            })

        absent = [
            str(s)[:80] for s in (a.get("absent_sections") or [])[:6]
            if str(s).strip() and not cs.section_present(sections, lines, str(s))
        ]

        downgraded = False
        if verdict in RISK_LOWERING and not evidence and not (verdict == "not_applicable" and absent):
            downgraded = True
            rationale = (
                f"Model proposed '{verdict}' but cited no verifiable configuration evidence, "
                f"so this is treated as undetermined. Model reasoning: {rationale}"
            )[:1500]
            verdict = "undetermined"

        row = _row(c["id"], verdict, rationale)
        row.update({
            "evidence": evidence,
            "absent_sections": absent,
            "suggested_change": "" if downgraded else _clean_change(a.get("suggested_change")),
            "change_note": "" if downgraded else str(a.get("change_note") or "")[:400],
        })
        results.append(row)
    return results


def _row(cve_id: str, verdict: str, rationale: str) -> dict:
    return {
        "cve_id": cve_id, "verdict": verdict, "rationale": rationale,
        "evidence": [], "absent_sections": [], "suggested_change": "", "change_note": "",
    }


def assess_batch(
    llm,
    device: dict,
    content: str,
    style: str,
    sections: list[cs.Section],
    cves: list[dict],
    requirements: dict[str, dict],
    fba_findings: list[dict] | None = None,
    line_budget: int = 350,
) -> list[dict] | None:
    """Assess up to ASSESS_BATCH CVEs. Returns None when the LLM call itself
    failed (caller should retry later rather than persist a non-answer)."""
    wanted, keywords = [], []
    for c in cves:
        req = requirements.get(c["id"], {})
        wanted += req.get("config_sections", [])
        keywords += req.get("keywords", [])
    shown = cs.select_lines(content, style, sections, wanted, keywords, budget=line_budget)
    excerpt = cs.render_excerpt(content, sections, shown)
    prompt = build_assessment_prompt(
        device, style, cs.section_index(sections), excerpt, cves, requirements, fba_findings
    )
    raw = _chat_json(llm, prompt, max_tokens=3000)
    if raw is None:
        return None
    return validate_assessments(raw, cves, content, sections, shown)


def assess_device(
    llm,
    device: dict,
    content: str,
    cves: list[dict],
    requirements: dict[str, dict],
    fba_findings: list[dict] | None = None,
    line_budget: int = 350,
) -> list[dict]:
    """Assess every CVE in `cves` against an already-redacted config.

    CVEs whose requirements say config_independent skip the device-level call.
    CVEs in a batch whose LLM call failed are left out (retried next cycle).
    """
    style, sections = cs.parse_sections(content)
    results, pending = [], []
    for c in cves:
        req = requirements.get(c["id"])
        if req is None:
            continue   # requirements not available yet — retry next cycle
        if not req.get("config_dependent", True):
            results.append(_row(
                c["id"], "config_independent",
                f"Exploitability does not depend on device configuration "
                f"({req.get('component') or 'core component'}). Upgrade to a fixed release.",
            ))
        else:
            pending.append(c)

    # Keep CVEs that look at the same config area in the same batch → smaller excerpts
    pending.sort(key=lambda c: (
        (requirements[c["id"]].get("config_sections") or [""])[0].lower(),
        -(c.get("score") or 0),
    ))
    for i in range(0, len(pending), ASSESS_BATCH):
        batch = pending[i:i + ASSESS_BATCH]
        rows = assess_batch(llm, device, content, style, sections, batch,
                            requirements, fba_findings, line_budget)
        if rows:
            results.extend(rows)
    return results
