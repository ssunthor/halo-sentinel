"""Device-config text handling for config-aware CVE analysis (stdlib only).

Three jobs, all deterministic — no LLM, no network:

  redact(content)          strip secrets (hashes, PSKs, keys, SNMP communities)
                           line-for-line, so line numbers stay stable. Only the
                           redacted text is ever stored, prompted, or displayed.
  parse_sections(content)  split a config into addressable sections with
                           1-indexed inclusive line ranges. Understands FortiOS
                           config/edit/end, flat `set ...` (Junos/PAN-OS),
                           curly-brace Junos, and indented Cisco/Arista style.
  select_lines(...)        pick the lines worth showing the LLM for a set of
                           wanted section names + keywords, within a line budget.

Everything downstream (evidence citations, UI snippets) addresses the config by
line number into the *redacted* text, which is what makes LLM-cited evidence
verifiable: a snippet is always sliced from the real config, never quoted by
the model.
"""

import hashlib
import re
from dataclasses import dataclass

REDACTED = "<redacted>"

# Lines above this are trimmed to matching sub-blocks / keyword windows.
SECTION_LINE_CAP = 120
KEYWORD_WINDOW = 6
MIN_KEYWORD_LEN = 4


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")

# (pattern, replacement) — applied per line, in order.
_REDACTIONS = [
    # FortiOS encrypted blobs: set password ENC abc123==
    (re.compile(r"\bENC\s+\S+"), f"ENC {REDACTED}"),
    # FortiOS plaintext secrets
    (re.compile(
        r"^(\s*set\s+(?:password|passwd|psksecret|secret|auth-pwd|priv-pwd|"
        r"key|private-key|passphrase|ppk-secret)\s+)(?!ENC\b).+$", re.I),
     rf"\g<1>{REDACTED}"),
    # Junos quoted secrets
    (re.compile(
        r'((?:encrypted-password|secret|authentication-key|ascii-text|'
        r'pre-shared-key|simple-password)\s+)"[^"]*"', re.I),
     rf'\g<1>"{REDACTED}"'),
    # Cisco/Arista: password|secret|key [type] VALUE
    (re.compile(
        r"\b((?:password|secret|key-string|pre-shared-key|key)\s+(?:\d{1,2}\s+)?)"
        r"(?!<redacted>)(\S+)\s*$", re.I),
     rf"\g<1>{REDACTED}"),
    # SNMP communities (Cisco / Junos set style)
    (re.compile(r"\b(snmp-server\s+community\s+)\S+", re.I), rf"\g<1>{REDACTED}"),
    (re.compile(r"\b(snmp\s+community\s+)\S+", re.I), rf"\g<1>{REDACTED}"),
    # PAN-OS / generic XML secrets
    (re.compile(
        r"<(phash|password|secret|private-key|key|bind-password)>[^<]+</\1>", re.I),
     rf"<\g<1>>{REDACTED}</\g<1>>"),
    # crypt / Junos $9$ hashes anywhere
    (re.compile(r"\$(?:1|5|6|8|9|2[aby]|sha1)\$[^\s\"'<]+"), REDACTED),
]


def redact(content: str) -> tuple[str, int]:
    """Return (redacted_text, redaction_count). Line count is preserved."""
    out = []
    count = 0
    in_pem = False
    for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
                out.append(line)
            else:
                out.append(REDACTED)
                count += 1
            continue
        if _PEM_BEGIN.search(line):
            # single-line PEM (BEGIN and END on one line) stays out of PEM mode
            if not _PEM_END.search(line):
                in_pem = True
            out.append(line)
            continue
        for pattern, repl in _REDACTIONS:
            line, n = pattern.subn(repl, line)
            count += n
        out.append(line)
    return "\n".join(out), count


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Section:
    path: str    # e.g. "vpn ssl settings", "line vty 0 4", "system services"
    start: int   # 1-indexed, inclusive
    end: int     # 1-indexed, inclusive

    def __len__(self) -> int:
        return self.end - self.start + 1


def detect_style(lines: list[str]) -> str:
    """One of: fortios | set | brace | indented."""
    nonblank = [l for l in lines if l.strip()]
    if not nonblank:
        return "indented"
    n_config = sum(1 for l in lines if l.startswith("config "))
    n_end = sum(1 for l in lines if l.strip() == "end")
    if n_config >= 3 and n_end >= 3:
        return "fortios"
    n_set = sum(1 for l in nonblank if l.startswith(("set ", "delete ")))
    if n_set / len(nonblank) > 0.5:
        return "set"
    n_open = sum(1 for l in nonblank if l.rstrip().endswith("{"))
    n_close = sum(1 for l in nonblank if l.strip().startswith("}"))
    if n_open >= 5 and n_close >= 5:
        return "brace"
    return "indented"


def _odd_quotes(line: str) -> bool:
    return len(re.findall(r'(?<!\\)"', line)) % 2 == 1


def _parse_fortios(lines: list[str]) -> list[Section]:
    sections = []
    depth = 0
    start = 0
    path = ""
    in_quote = False   # multi-line quoted values (banners, certs) can contain "end"
    header_end = 0
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if in_quote:
            if _odd_quotes(raw):
                in_quote = False
            continue
        if depth == 0:
            if s.startswith("#") and not sections and i == header_end + 1:
                header_end = i
            elif raw.startswith("config "):
                depth, start, path = 1, i, s[len("config "):].strip()
        else:
            if s.startswith("config "):
                depth += 1
            elif s == "end":
                depth -= 1
                if depth == 0:
                    sections.append(Section(path, start, i))
            elif _odd_quotes(raw):
                in_quote = True
    if depth > 0:   # truncated config — keep what we have
        sections.append(Section(path, start, len(lines)))
    if header_end:
        sections.insert(0, Section("header", 1, header_end))
    return sections


def _parse_set(lines: list[str]) -> list[Section]:
    """Flat `set a b c ...` configs: group consecutive lines by their first
    two hierarchy tokens (e.g. `set system services ...` → "system services")."""
    sections = []
    cur_path, cur_start = None, 0
    for i, raw in enumerate(lines, 1):
        toks = raw.split()
        if len(toks) >= 2 and toks[0] in ("set", "delete"):
            path = " ".join(toks[1:3])
        else:
            path = None
        if path != cur_path:
            if cur_path:
                sections.append(Section(cur_path, cur_start, i - 1))
            cur_path, cur_start = path, i
    if cur_path:
        sections.append(Section(cur_path, cur_start, len(lines)))
    return sections


def _parse_brace(lines: list[str]) -> list[Section]:
    """Curly-brace (Junos) configs: emit depth-1 and depth-2 blocks. They overlap
    on purpose — selection works on line sets, and depth-2 paths like
    "system services" are what CVE advisories actually name."""
    sections = []
    stack: list[tuple[str, int]] = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.endswith("{"):
            name = s[:-1].strip()
            stack.append((name, i))
        elif s.startswith("}") and stack:
            name, start = stack.pop()
            depth = len(stack) + 1
            if depth <= 2:
                path = " ".join([n for n, _ in stack] + [name])
                sections.append(Section(path, start, i))
    sections.sort(key=lambda sec: (sec.start, -sec.end))
    return sections


def _parse_indented(lines: list[str]) -> list[Section]:
    """Cisco/Arista style: a column-0 line owns the indented lines under it."""
    sections = []
    cur_path, cur_start, last_content = None, 0, 0
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("!"):
            continue
        if raw[0] in (" ", "\t") and cur_path:
            last_content = i
            continue
        if cur_path:
            sections.append(Section(cur_path, cur_start, last_content))
        cur_path, cur_start, last_content = s, i, i
    if cur_path:
        sections.append(Section(cur_path, cur_start, last_content))
    return sections


_PARSERS = {
    "fortios": _parse_fortios,
    "set": _parse_set,
    "brace": _parse_brace,
    "indented": _parse_indented,
}


def parse_sections(content: str) -> tuple[str, list[Section]]:
    """Return (style, sections)."""
    lines = content.split("\n")
    style = detect_style(lines)
    return style, _PARSERS[style](lines)


def section_index(sections: list[Section], limit: int = 320) -> list[str]:
    """Distinct section paths, in config order — lets the LLM see what exists
    (and therefore what is absent) without seeing the whole config."""
    seen, out = set(), []
    for sec in sections:
        key = sec.path.lower()
        if key not in seen:
            seen.add(key)
            out.append(sec.path)
            if len(out) >= limit:
                break
    return out


def enclosing_section(sections: list[Section], start: int, end: int) -> str:
    """Path of the tightest section containing [start, end], or ''."""
    best = None
    for sec in sections:
        if sec.start <= start and end <= sec.end:
            if best is None or len(sec) < len(best):
                best = sec
    return best.path if best else ""


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def _norm(name: str) -> str:
    name = re.sub(r"\s+", " ", name.strip().lower())
    for prefix in ("config ", "set ", "show "):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


def name_matches(wanted: str, path: str) -> bool:
    w, p = _norm(wanted), _norm(path)
    if not w or not p:
        return False
    if w in p:
        return True
    # "vpn ssl settings portal" still targets the "vpn ssl settings" section
    return len(p.split()) >= 2 and p in w


def section_present(sections: list[Section], lines: list[str], name: str) -> bool:
    """True if `name` exists as a section path or appears on any config line."""
    if any(name_matches(name, sec.path) for sec in sections):
        return True
    n = _norm(name)
    return bool(n) and any(n in l.lower() for l in lines)


def _clean_keywords(keywords: list[str]) -> list[str]:
    out = []
    for k in keywords or []:
        k = str(k).strip().lower()
        if len(k) >= MIN_KEYWORD_LEN and k not in out:
            out.append(k)
    return out[:16]


def _fortios_subblocks(lines: list[str], sec: Section) -> list[tuple[int, int]]:
    """(start, end) of each depth-1 `edit ... next` block inside a section."""
    blocks = []
    depth = 0
    start = 0
    for i in range(sec.start + 1, sec.end):
        s = lines[i - 1].strip()
        if s.startswith("config "):
            depth += 1
        elif s == "end":
            depth -= 1
        elif depth == 0 and s.startswith("edit "):
            start = i
        elif depth == 0 and s == "next" and start:
            blocks.append((start, i))
            start = 0
    return blocks


def _trim_section(lines: list[str], sec: Section, keywords: list[str], style: str) -> set[int]:
    """Line numbers to show for an oversized section."""
    def hit(i: int) -> bool:
        low = lines[i - 1].lower()
        return any(k in low for k in keywords)

    keep: set[int] = {sec.start, sec.end}
    if style == "fortios":
        for b_start, b_end in _fortios_subblocks(lines, sec):
            if any(hit(i) for i in range(b_start, b_end + 1)):
                keep.update(range(b_start, b_end + 1))
    if len(keep) <= 2:
        for i in range(sec.start, sec.end + 1):
            if hit(i):
                keep.update(range(max(sec.start, i - KEYWORD_WINDOW),
                                  min(sec.end, i + KEYWORD_WINDOW) + 1))
    if len(keep) <= 2:
        keep.update(range(sec.start, min(sec.end, sec.start + SECTION_LINE_CAP - 1) + 1))
    if len(keep) > SECTION_LINE_CAP:
        keep = set(sorted(keep)[:SECTION_LINE_CAP])
    return keep


def select_lines(
    content: str,
    style: str,
    sections: list[Section],
    wanted_sections: list[str],
    keywords: list[str],
    budget: int = 350,
) -> set[int]:
    """Line numbers (1-indexed) to show the LLM, at most ~`budget` of them.

    Sections matched by name come first, then sections that merely contain a
    keyword. Oversized sections are trimmed to keyword-matching sub-blocks.
    """
    lines = content.split("\n")
    keywords = _clean_keywords(keywords)

    by_name, by_keyword = [], []
    for sec in sections:
        if sec.path == "header":
            continue
        if any(name_matches(w, sec.path) for w in wanted_sections or []):
            by_name.append(sec)
        elif keywords and any(
            any(k in lines[i - 1].lower() for k in keywords)
            for i in range(sec.start, sec.end + 1)
        ):
            by_keyword.append(sec)

    chosen: set[int] = set()
    for sec in sections:
        if sec.path == "header":
            chosen.update(range(sec.start, sec.end + 1))
    for sec in by_name + by_keyword:
        if len(sec) > SECTION_LINE_CAP:
            add = _trim_section(lines, sec, keywords, style)
        else:
            add = set(range(sec.start, sec.end + 1))
        if chosen and len(chosen | add) > budget:
            continue
        chosen |= add
    return chosen


def render_excerpt(content: str, sections: list[Section], chosen: set[int]) -> str:
    """Numbered excerpt for the prompt. Gaps are marked so the model knows the
    excerpt is not contiguous; every shown line carries its real line number."""
    lines = content.split("\n")
    out = []
    prev = None
    for i in sorted(chosen):
        if i < 1 or i > len(lines):
            continue
        if prev is None or i != prev + 1:
            label = enclosing_section(sections, i, i)
            out.append(f"   ...  [{label or 'config'}]")
        out.append(f"{i:>5}| {lines[i - 1]}")
        prev = i
    return "\n".join(out)


def slice_lines(content: str, start: int, end: int) -> str:
    lines = content.split("\n")
    return "\n".join(lines[start - 1:end])
