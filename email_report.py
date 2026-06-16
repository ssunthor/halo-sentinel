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
# HTML email builder  (dashboard dark palette)
# ---------------------------------------------------------------------------

# Color tokens matching the dashboard (gray-950/900/800, green-400/500)
_C = dict(
    bg_outer   = "#030712",   # near-black wrapper
    bg_card    = "#111827",   # gray-900
    bg_section = "#1f2937",   # gray-800 alternate row
    border     = "#374151",   # gray-700
    text_pri   = "#f9fafb",   # white
    text_sec   = "#9ca3af",   # gray-400
    text_label = "#6b7280",   # gray-500
    accent     = "#34d399",   # emerald-400
    divider    = "#22c55e",   # green-500
)


def _td(bg, border, padding, style_extra, content):
    """Emit a <td> with both bgcolor attr and inline background-color."""
    return (
        f'<td bgcolor="{bg}" style="background-color:{bg};border:{border};'
        f'padding:{padding};{style_extra}">{content}</td>'
    )


def _build_html(estate_stats: dict, leaderboard: list, preamble_html: str, subject: str) -> str:
    C       = _C
    e       = estate_stats
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Preamble ─────────────────────────────────────────────────────────────
    preamble_block = ""
    if not _is_empty_html(preamble_html):
        # Make images responsive
        safe = re.sub(
            r'<img\b([^>]*?)>',
            r'<img\1 style="max-width:100%;height:auto;display:block;margin:8px 0;border-radius:4px;">',
            preamble_html,
        )
        preamble_block = (
            f'<tr>'
            f'<td bgcolor="{C["bg_card"]}" style="background-color:{C["bg_card"]};'
            f'padding:24px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;'
            f'font-size:14px;line-height:1.7;color:{C["text_pri"]};">'
            f'{safe}'
            f'</td></tr>'
        )

    # ── Estate summary ────────────────────────────────────────────────────────
    vuln      = int(e.get("vulnerable_devices", 0) or 0)
    total_dev = int(e.get("total_devices", 0) or 0)
    vuln_pct  = f" ({round(100 * vuln / total_dev)}%)" if total_dev else ""
    peak      = float(e.get("max_score") or 0.0)

    stat_rows = [
        ("Clients Scanned",      f"{int(e.get('total_tenants', 0) or 0):,}"),
        ("Total Devices",        f"{total_dev:,}"),
        ("Vulnerable Devices",   f"{vuln:,}{vuln_pct}"),
        ("Critical (&ge;&nbsp;9.0)", f"{int(e.get('critical_devices', 0) or 0):,}"),
        ("Total CVE Instances",  f"{int(e.get('total_cve_instances', 0) or 0):,}"),
        ("Peak CVE Score",
         f'<span style="background:{_score_color(peak)};color:#ffffff;'
         f'padding:2px 10px;border-radius:4px;font-weight:bold;font-size:13px;">{peak:.1f}</span>'),
    ]

    estate_rows_html = ""
    for i, (label, value) in enumerate(stat_rows):
        bg = C["bg_section"] if i % 2 == 0 else C["bg_card"]
        cell_base = (
            f'font-family:Arial,Helvetica,sans-serif;font-size:13px;'
        )
        estate_rows_html += (
            f'<tr>'
            f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
            f'padding:10px 14px;{cell_base}color:{C["text_label"]};">{label}</td>'
            f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
            f'padding:10px 14px;{cell_base}color:{C["text_pri"]};font-weight:600;'
            f'text-align:right;">{value}</td>'
            f'</tr>\n'
        )

    estate_padding = "24px 32px 0 32px" if leaderboard else "24px 32px"

    # ── Leaderboard ───────────────────────────────────────────────────────────
    leaderboard_block = ""
    if leaderboard:
        lb_rows = ""
        for i, row in enumerate(leaderboard[:10]):
            score   = float(row.get("max_score") or 0.0)
            vuln_c  = int(row.get("vulnerable_devices", 0))
            total_c = int(row.get("total_devices", 0))
            name    = str(row.get("name") or "—")
            bg      = C["bg_section"] if i % 2 == 0 else C["bg_card"]
            sc_bg   = _score_color(score)
            lb_rows += (
                f'<tr>'
                f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
                f'padding:9px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;'
                f'color:{C["text_sec"]};text-align:center;">{i + 1}</td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
                f'padding:9px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;'
                f'color:{C["text_pri"]};">{name}</td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
                f'padding:9px 12px;text-align:center;">'
                f'<span style="background:{sc_bg};color:#ffffff;padding:2px 10px;border-radius:4px;'
                f'font-size:12px;font-weight:bold;font-family:Arial,Helvetica,sans-serif;">{score:.1f}</span>'
                f'</td>'
                f'<td bgcolor="{bg}" style="background-color:{bg};border:1px solid {C["border"]};'
                f'padding:9px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;'
                f'color:{C["text_label"]};text-align:center;">{vuln_c:,}&nbsp;/&nbsp;{total_c:,}</td>'
                f'</tr>\n'
            )

        top_n = min(10, len(leaderboard))
        th_style = (
            f'border:1px solid {C["border"]};padding:8px 12px;'
            f'font-family:Arial,Helvetica,sans-serif;font-size:10px;color:{C["text_sec"]};'
            f'text-transform:uppercase;letter-spacing:0.08em;font-weight:600;'
        )
        leaderboard_block = (
            f'<tr>'
            f'<td bgcolor="{C["bg_card"]}" style="background-color:{C["bg_card"]};padding:24px 32px 32px 32px;">'
            f'<div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;'
            f'color:{C["text_sec"]};text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;">'
            f'Top {top_n} Clients by CVE Score</div>'
            f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
            f'<thead><tr bgcolor="#000000" style="background-color:#000000;">'
            f'<th style="{th_style}text-align:center;">#</th>'
            f'<th style="{th_style}text-align:left;">Client</th>'
            f'<th style="{th_style}text-align:center;">Peak Score</th>'
            f'<th style="{th_style}text-align:center;">Vuln&nbsp;/&nbsp;Total</th>'
            f'</tr></thead>'
            f'<tbody>{lb_rows}</tbody>'
            f'</table>'
            f'</td></tr>'
        )

    # ── Full HTML document ────────────────────────────────────────────────────
    return "\n".join([
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">',
        f'<title>{subject}</title>',
        '</head>',
        f'<body bgcolor="{C["bg_outer"]}" style="margin:0;padding:0;background-color:{C["bg_outer"]};">',
        f'<table width="100%" cellpadding="0" cellspacing="0" border="0"',
        f'       bgcolor="{C["bg_outer"]}" style="background-color:{C["bg_outer"]};">',
        f'<tr><td align="center" style="padding:24px 16px;">',
        f'<table width="640" cellpadding="0" cellspacing="0" border="0"',
        f'       bgcolor="{C["bg_card"]}" style="background-color:{C["bg_card"]};max-width:640px;width:100%;">',

        # Header
        f'<tr>',
        f'<td bgcolor="#000000" style="background-color:#000000;padding:24px 32px;'
        f'border-bottom:2px solid {C["divider"]};">',
        f'<div style="font-family:monospace;font-size:22px;font-weight:bold;color:#ffffff;letter-spacing:3px;">'
        f'DEFENSE HALO</div>',
        f'<div style="font-family:monospace;font-size:10px;color:{C["accent"]};'
        f'letter-spacing:4px;text-transform:uppercase;margin-top:4px;">Customer CVE Analyzer</div>',
        f'<div style="margin-top:14px;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:{C["text_sec"]};">'
        f'{subject}</div>',
        f'</td></tr>',

        preamble_block,

        # Estate summary
        f'<tr>',
        f'<td bgcolor="{C["bg_card"]}" style="background-color:{C["bg_card"]};padding:{estate_padding};">',
        f'<div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;'
        f'color:{C["text_sec"]};text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;'
        f'padding-bottom:8px;border-bottom:1px solid {C["border"]};">Estate Summary</div>',
        f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">',
        estate_rows_html,
        f'</table></td></tr>',

        leaderboard_block,

        # Footer
        f'<tr>',
        f'<td bgcolor="#000000" style="background-color:#000000;padding:14px 32px;'
        f'border-top:1px solid {C["border"]};">',
        f'<p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:{C["text_label"]};">',
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

    # Inner: alternative (plain-text + HTML; email clients pick best version)
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
