"""
Email report sender for the Defense Halo CVE Analyzer.

send_report_email() is the sole public entry point. It builds a multipart
HTML + plain-text email with an Excel attachment and delivers it via SMTP.
"""

import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import unescape


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_color(score: float) -> str:
    if score >= 9.0: return "#dc2626"
    if score >= 7.0: return "#ea580c"
    if score >= 4.0: return "#d97706"
    return "#16a34a"


def _html_to_text(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    text = re.sub(r"\s+", " ", text)
    return unescape(text).strip()


def _is_empty_html(html: str) -> bool:
    return not _html_to_text(html)


# ---------------------------------------------------------------------------
# Subject token substitution
# ---------------------------------------------------------------------------

def _render_subject(template: str, estate_stats: dict) -> str:
    e   = estate_stats
    now = datetime.now(timezone.utc)
    return (
        template
        .replace("{date}",          now.strftime("%Y-%m-%d"))
        .replace("{datetime}",      now.strftime("%Y-%m-%d %H:%M UTC"))
        .replace("{total_clients}", str(e.get("total_tenants", 0)))
        .replace("{vulnerable}",    str(e.get("vulnerable_devices", 0)))
        .replace("{critical}",      str(e.get("critical_devices", 0)))
        .replace("{peak_score}",    f"{(e.get('max_score') or 0.0):.1f}")
    )


# ---------------------------------------------------------------------------
# HTML email — dashboard dark palette
#
# Matches the UI exactly:
#   bg-black (#000000) body, gray-900 (#111827) panels,
#   gray-800 (#1f2937) alternating rows, gray-700 (#374151) borders,
#   green-500 (#22c55e) accent, emerald-400 (#34d399) subheading,
#   monospace font for all data / section labels.
# ---------------------------------------------------------------------------

# Shared font stacks
_MONO  = "'Courier New', Courier, monospace"
_SANS  = "Arial, Helvetica, sans-serif"

# Color palette (mirrors Tailwind classes used by the dashboard)
_BG        = "#000000"   # body / outer wrapper  (bg-black)
_PANEL     = "#111827"   # panel background      (bg-gray-900)
_ROW_ALT   = "#1f2937"   # alternate row         (bg-gray-800)
_BORDER    = "#374151"   # table / divider       (border-gray-700)
_BORDER_DIM= "#1f2937"   # subtle border         (border-gray-800)
_GREEN     = "#22c55e"   # primary accent        (text-green-500)
_EMERALD   = "#34d399"   # secondary accent      (text-emerald-400)
_WHITE     = "#ffffff"
_GRAY_100  = "#f3f4f6"   # primary text
_GRAY_400  = "#9ca3af"   # secondary text
_GRAY_500  = "#6b7280"   # labels / dim text
_GRAY_600  = "#4b5563"   # footer / muted


def _cell(bg, extra_style, content):
    """Emit a <td> with both bgcolor attr and inline background-color."""
    return (
        f'<td bgcolor="{bg}" style="background-color:{bg};{extra_style}">'
        f'{content}</td>'
    )


def _label_row(text: str) -> str:
    """Section separator that looks like the dashboard's uppercase tracking labels."""
    return (
        f'<tr>'
        f'<td colspan="4" bgcolor="{_BG}" style="background-color:{_BG};'
        f'padding:20px 24px 8px 24px;'
        f'font-family:{_MONO};font-size:10px;font-weight:bold;color:{_GRAY_500};'
        f'text-transform:uppercase;letter-spacing:3px;'
        f'border-bottom:1px solid {_BORDER_DIM};">'
        f'{text}'
        f'</td></tr>'
    )


def _build_html(estate_stats: dict, leaderboard: list, preamble_html: str, subject: str) -> str:
    e       = estate_stats
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Preamble ─────────────────────────────────────────────────────────────
    preamble_block = ""
    if not _is_empty_html(preamble_html):
        safe = re.sub(
            r'<img\b([^>]*?)>',
            r'<img\1 style="max-width:100%;height:auto;display:block;margin:10px 0;border-radius:4px;">',
            preamble_html,
        )
        preamble_block = (
            f'<tr>'
            f'<td bgcolor="{_PANEL}" style="background-color:{_PANEL};'
            f'padding:20px 24px;border-bottom:1px solid {_BORDER_DIM};'
            f'font-family:{_SANS};font-size:14px;line-height:1.7;color:{_GRAY_100};">'
            f'{safe}'
            f'</td></tr>'
        )

    # ── Estate summary ────────────────────────────────────────────────────────
    vuln      = int(e.get("vulnerable_devices", 0) or 0)
    total_dev = int(e.get("total_devices", 0) or 0)
    vuln_pct  = f" ({round(100 * vuln / total_dev)}%)" if total_dev else ""
    peak      = float(e.get("max_score") or 0.0)

    stat_rows_data = [
        ("Clients Scanned",       f"{int(e.get('total_tenants', 0) or 0):,}"),
        ("Total Devices",         f"{total_dev:,}"),
        ("Vulnerable Devices",    f"{vuln:,}{vuln_pct}"),
        ("Critical (&ge; 9.0)",   f"{int(e.get('critical_devices', 0) or 0):,}"),
        ("Total CVE Instances",   f"{int(e.get('total_cve_instances', 0) or 0):,}"),
        ("Peak CVE Score",
         f'<span style="display:inline-block;background:{_score_color(peak)};color:{_WHITE};'
         f'padding:1px 10px;border-radius:3px;font-family:{_MONO};font-weight:bold;font-size:13px;">'
         f'{peak:.1f}</span>'),
    ]

    estate_rows = ""
    for i, (label, value) in enumerate(stat_rows_data):
        bg = _ROW_ALT if i % 2 == 0 else _PANEL
        estate_rows += (
            f'<tr>'
            f'<td bgcolor="{bg}" style="background-color:{bg};'
            f'border:1px solid {_BORDER};padding:9px 14px;'
            f'font-family:{_MONO};font-size:12px;color:{_GRAY_500};">{label}</td>'
            f'<td bgcolor="{bg}" style="background-color:{bg};'
            f'border:1px solid {_BORDER};padding:9px 14px;'
            f'font-family:{_MONO};font-size:12px;color:{_GRAY_100};'
            f'font-weight:bold;text-align:right;">{value}</td>'
            f'</tr>\n'
        )

    # ── Leaderboard ───────────────────────────────────────────────────────────
    leaderboard_block = ""
    if leaderboard:
        th_style = (
            f'border:1px solid {_BORDER};padding:8px 14px;'
            f'font-family:{_MONO};font-size:10px;color:{_GRAY_500};'
            f'text-transform:uppercase;letter-spacing:2px;font-weight:bold;'
        )
        lb_rows = ""
        for i, row in enumerate(leaderboard[:10]):
            score   = float(row.get("max_score") or 0.0)
            vuln_c  = int(row.get("vulnerable_devices", 0))
            total_c = int(row.get("total_devices", 0))
            name    = str(row.get("name") or "—")
            bg      = _ROW_ALT if i % 2 == 0 else _PANEL
            sc_bg   = _score_color(score)
            lb_rows += (
                f'<tr>'
                f'<td bgcolor="{bg}" style="background-color:{bg};'
                f'border:1px solid {_BORDER};padding:8px 14px;'
                f'font-family:{_MONO};font-size:12px;color:{_GRAY_500};'
                f'text-align:center;">{i + 1}</td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};'
                f'border:1px solid {_BORDER};padding:8px 14px;'
                f'font-family:{_MONO};font-size:12px;color:{_GRAY_100};">{name}</td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};'
                f'border:1px solid {_BORDER};padding:8px 14px;text-align:center;">'
                f'<span style="display:inline-block;background:{sc_bg};color:{_WHITE};'
                f'padding:1px 10px;border-radius:3px;font-family:{_MONO};'
                f'font-size:12px;font-weight:bold;">{score:.1f}</span></td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};'
                f'border:1px solid {_BORDER};padding:8px 14px;'
                f'font-family:{_MONO};font-size:12px;color:{_GRAY_500};'
                f'text-align:center;">{vuln_c:,}&nbsp;/&nbsp;{total_c:,}</td>'
                f'</tr>\n'
            )

        top_n = min(10, len(leaderboard))
        leaderboard_block = (
            _label_row(f"Top {top_n} Clients by CVE Score") +
            f'<tr><td bgcolor="{_BG}" style="background-color:{_BG};padding:0 24px 24px 24px;">'
            f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
            f'<thead><tr bgcolor="{_BG}" style="background-color:{_BG};">'
            f'<th style="{th_style}text-align:center;">#</th>'
            f'<th style="{th_style}text-align:left;">Client</th>'
            f'<th style="{th_style}text-align:center;">Peak Score</th>'
            f'<th style="{th_style}text-align:center;">Vuln / Total</th>'
            f'</tr></thead>'
            f'<tbody>{lb_rows}</tbody>'
            f'</table></td></tr>'
        )

    return "\n".join([
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">',
        f'<title>{subject}</title>',
        '</head>',
        f'<body bgcolor="{_BG}" style="margin:0;padding:0;background-color:{_BG};">',

        # ── Outer wrapper ──
        f'<table width="100%" cellpadding="0" cellspacing="0" border="0"',
        f'       bgcolor="{_BG}" style="background-color:{_BG};">',
        f'<tr><td align="center" style="padding:24px 16px;">',

        # ── Card ──
        f'<table width="640" cellpadding="0" cellspacing="0" border="0"',
        f'       bgcolor="{_BG}" style="background-color:{_BG};max-width:640px;width:100%;'
        f'border:1px solid {_BORDER_DIM};">',

        # ── Header ── matches the nav bar exactly
        f'<tr>',
        f'<td bgcolor="{_BG}" style="background-color:{_BG};padding:24px 24px 20px 24px;'
        f'border-bottom:2px solid {_GREEN};">',
        f'<div style="font-family:{_MONO};font-size:22px;font-weight:bold;'
        f'color:{_WHITE};letter-spacing:4px;">DEFENSE HALO</div>',
        f'<div style="font-family:{_MONO};font-size:10px;color:{_EMERALD};'
        f'letter-spacing:5px;text-transform:uppercase;margin-top:3px;">Customer CVE Analyzer</div>',
        f'<div style="margin-top:14px;font-family:{_MONO};font-size:12px;color:{_GRAY_400};">'
        f'{subject}</div>',
        f'</td></tr>',

        # ── Preamble (if any) ──
        preamble_block,

        # ── Estate summary section label ──
        _label_row("Estate Summary"),

        # ── Estate summary table ──
        f'<tr><td bgcolor="{_BG}" style="background-color:{_BG};padding:0 24px 24px 24px;">',
        f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">',
        estate_rows,
        f'</table></td></tr>',

        # ── Leaderboard ──
        leaderboard_block,

        # ── Footer ──
        f'<tr>',
        f'<td bgcolor="{_BG}" style="background-color:{_BG};padding:14px 24px;'
        f'border-top:1px solid {_BORDER_DIM};">',
        f'<p style="margin:0;font-family:{_MONO};font-size:10px;color:{_GRAY_600};">',
        f'Report generated {now_str} &middot; Defense Halo Customer CVE Analyzer',
        f'</p></td></tr>',

        f'</table>',
        f'</td></tr></table>',
        f'</body>',
        f'</html>',
    ])


# ---------------------------------------------------------------------------
# Plain-text fallback
# ---------------------------------------------------------------------------

def _build_plain(estate_stats: dict, leaderboard: list, preamble_html: str) -> str:
    e     = estate_stats
    lines = []

    preamble_text = _html_to_text(preamble_html)
    if preamble_text:
        lines += [preamble_text, ""]

    vuln      = int(e.get("vulnerable_devices", 0) or 0)
    total_dev = int(e.get("total_devices", 0) or 0)
    vuln_pct  = f" ({round(100 * vuln / total_dev)}%)" if total_dev else ""

    lines += [
        "=" * 60,
        "ESTATE SUMMARY",
        "=" * 60,
        f"  Clients scanned     : {int(e.get('total_tenants', 0) or 0):,}",
        f"  Total devices       : {total_dev:,}",
        f"  Vulnerable devices  : {vuln:,}{vuln_pct}",
        f"  Critical (>= 9.0)   : {int(e.get('critical_devices', 0) or 0):,}",
        f"  Total CVE instances : {int(e.get('total_cve_instances', 0) or 0):,}",
        f"  Peak CVE score      : {float(e.get('max_score') or 0.0):.1f}",
        "",
    ]

    if leaderboard:
        lines += ["TOP 10 CLIENTS BY CVE SCORE", "-" * 60]
        for i, row in enumerate(leaderboard[:10], 1):
            score   = float(row.get("max_score") or 0.0)
            vuln_c  = int(row.get("vulnerable_devices", 0))
            total_c = int(row.get("total_devices", 0))
            lines.append(
                f"  {i:2}. {str(row.get('name', '—')):<35} "
                f"Score: {score:4.1f}   Vuln: {vuln_c}/{total_c}"
            )
        lines.append("")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines += ["=" * 60, f"Report generated {now_str}", "=" * 60]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core send function
# ---------------------------------------------------------------------------

def send_report_email(
    config: dict,
    xlsx_bytes: bytes,
    estate_stats: dict,
    leaderboard: list,
) -> None:
    """
    Build and deliver the CVE report email (HTML + plain-text + Excel attachment).

    config keys:
        smtp_host, smtp_port, smtp_tls ("none"|"starttls"|"tls"),
        smtp_username, smtp_password,
        from_address, to_addresses, cc_addresses, bcc_addresses,
        subject, body_preamble  (HTML from WYSIWYG editor)
    """
    smtp_host = (config.get("smtp_host") or "").strip()
    smtp_port = int(config.get("smtp_port") or 587)
    tls_mode  = (config.get("smtp_tls") or "starttls").lower()
    username  = (config.get("smtp_username") or "").strip()
    password  = config.get("smtp_password") or ""

    from_addr = (config.get("from_address") or "").strip()
    to_addrs  = [a.strip() for a in (config.get("to_addresses")  or []) if a.strip()]
    cc_addrs  = [a.strip() for a in (config.get("cc_addresses")  or []) if a.strip()]
    bcc_addrs = [a.strip() for a in (config.get("bcc_addresses") or []) if a.strip()]

    if not smtp_host:  raise ValueError("SMTP host is not configured.")
    if not from_addr:  raise ValueError("From address is not configured.")
    if not to_addrs:   raise ValueError("No To recipients configured.")

    all_rcpt = to_addrs + cc_addrs + bcc_addrs

    preamble = config.get("body_preamble") or ""
    subject  = _render_subject(
        config.get("subject") or "Defense Halo CVE Report — {date}",
        estate_stats,
    )

    html_body  = _build_html(estate_stats, leaderboard, preamble, subject)
    plain_body = _build_plain(estate_stats, leaderboard, preamble)

    # Outer: mixed (carries the attachment)
    msg = MIMEMultipart("mixed")
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)
    msg["Subject"] = subject
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)

    # Inner: alternative (plain-text + HTML; clients pick best)
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(plain_body, "plain", "utf-8"))
    alt.attach(MIMEText(html_body,  "html",  "utf-8"))
    msg.attach(alt)

    # Excel attachment
    fname = f"cve_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    attachment = MIMEApplication(
        xlsx_bytes,
        Name=fname,
        _subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    attachment["Content-Disposition"] = f'attachment; filename="{fname}"'
    msg.attach(attachment)

    # SMTP delivery
    ctx = ssl.create_default_context()

    if tls_mode == "tls":
        smtp = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=30)
    else:
        smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=30)

    with smtp:
        smtp.ehlo()
        if tls_mode == "starttls":
            smtp.starttls(context=ctx)
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        smtp.sendmail(from_addr, all_rcpt, msg.as_bytes())
