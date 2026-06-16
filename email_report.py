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
    """Strip HTML tags for the plain-text fallback."""
    text = re.sub(r"<[^>]+>", " ", html or "")
    text = re.sub(r"\s+", " ", text)
    return unescape(text).strip()


def _is_empty_html(html: str) -> bool:
    return not _html_to_text(html)


# ---------------------------------------------------------------------------
# Subject token substitution
# ---------------------------------------------------------------------------

def _render_subject(template: str, estate_stats: dict) -> str:
    e = estate_stats
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
# HTML email builder
# ---------------------------------------------------------------------------

def _build_html(estate_stats: dict, leaderboard: list, preamble_html: str, subject: str) -> str:
    e       = estate_stats
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Preamble ──
    preamble_block = ""
    if not _is_empty_html(preamble_html):
        preamble_block = f"""
    <tr>
      <td style="padding:24px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.65;color:#374151;">
        {preamble_html}
      </td>
    </tr>"""

    # ── Estate summary rows ──
    vuln      = int(e.get("vulnerable_devices", 0) or 0)
    total_dev = int(e.get("total_devices", 0) or 0)
    vuln_pct  = f" ({round(100 * vuln / total_dev)} %)" if total_dev else ""
    peak      = float(e.get("max_score") or 0.0)

    stat_rows = [
        ("Clients Scanned",     f"{int(e.get('total_tenants', 0) or 0):,}"),
        ("Total Devices",       f"{total_dev:,}"),
        ("Vulnerable Devices",  f"{vuln:,}{vuln_pct}"),
        ("Critical (&ge; 9.0)", f"{int(e.get('critical_devices', 0) or 0):,}"),
        ("Total CVE Instances", f"{int(e.get('total_cve_instances', 0) or 0):,}"),
        ("Peak CVE Score",
         f'<span style="background:{_score_color(peak)};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;">'
         f'{peak:.1f}</span>'),
    ]

    estate_rows_html = ""
    for i, (label, value) in enumerate(stat_rows):
        bg = "#f9fafb" if i % 2 == 0 else "#ffffff"
        estate_rows_html += (
            f'<tr style="background:{bg};">'
            f'<td style="border:1px solid #e5e7eb;padding:9px 14px;font-family:Arial,Helvetica,sans-serif;'
            f'font-size:13px;color:#6b7280;">{label}</td>'
            f'<td style="border:1px solid #e5e7eb;padding:9px 14px;font-family:Arial,Helvetica,sans-serif;'
            f'font-size:13px;color:#111827;font-weight:600;text-align:right;">{value}</td>'
            f'</tr>\n'
        )

    estate_padding = "24px 32px 0 32px" if leaderboard else "24px 32px"

    # ── Leaderboard ──
    leaderboard_block = ""
    if leaderboard:
        lb_rows_html = ""
        for i, row in enumerate(leaderboard[:10]):
            score     = float(row.get("max_score") or 0.0)
            vuln_c    = int(row.get("vulnerable_devices", 0))
            total_c   = int(row.get("total_devices", 0))
            name      = str(row.get("name") or "—")
            bg        = "#f9fafb" if i % 2 == 0 else "#ffffff"
            sc_color  = _score_color(score)
            lb_rows_html += (
                f'<tr style="background:{bg};">'
                f'<td style="border:1px solid #e5e7eb;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;'
                f'font-size:13px;color:#9ca3af;text-align:center;">{i + 1}</td>'
                f'<td style="border:1px solid #e5e7eb;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;'
                f'font-size:13px;color:#111827;">{name}</td>'
                f'<td style="border:1px solid #e5e7eb;padding:8px 12px;text-align:center;">'
                f'<span style="background:{sc_color};color:#fff;padding:2px 10px;border-radius:4px;'
                f'font-size:12px;font-weight:bold;font-family:Arial,Helvetica,sans-serif;">{score:.1f}</span></td>'
                f'<td style="border:1px solid #e5e7eb;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;'
                f'font-size:13px;color:#6b7280;text-align:center;">{vuln_c:,}&nbsp;/&nbsp;{total_c:,}</td>'
                f'</tr>\n'
            )

        top_n = min(10, len(leaderboard))
        leaderboard_block = f"""
    <tr>
      <td style="padding:24px 32px 32px 32px;">
        <h2 style="font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#111827;
                   margin:0 0 12px 0;padding-bottom:8px;border-bottom:2px solid #e5e7eb;">
          Top {top_n} Clients by CVE Score
        </h2>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
          <thead>
            <tr style="background:#111827;">
              <th style="border:1px solid #374151;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;
                         font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;
                         text-align:center;">#</th>
              <th style="border:1px solid #374151;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;
                         font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;
                         text-align:left;">Client</th>
              <th style="border:1px solid #374151;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;
                         font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;
                         text-align:center;">Peak Score</th>
              <th style="border:1px solid #374151;padding:8px 12px;font-family:Arial,Helvetica,sans-serif;
                         font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;
                         text-align:center;">Vuln&nbsp;/&nbsp;Total</th>
            </tr>
          </thead>
          <tbody>
            {lb_rows_html}
          </tbody>
        </table>
      </td>
    </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{subject}</title>
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;">

<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">

  <table width="640" cellpadding="0" cellspacing="0" border="0"
         style="background-color:#ffffff;max-width:640px;width:100%;">

    <!-- Header -->
    <tr>
      <td style="background-color:#111827;padding:24px 32px;">
        <div style="font-family:monospace;font-size:20px;font-weight:bold;color:#ffffff;letter-spacing:2px;">
          DEFENSE HALO
        </div>
        <div style="font-family:monospace;font-size:10px;color:#34d399;letter-spacing:3px;
                    text-transform:uppercase;margin-top:4px;">
          Customer CVE Analyzer
        </div>
        <div style="margin-top:12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#d1d5db;">
          {subject}
        </div>
      </td>
    </tr>

    {preamble_block}

    <!-- Estate Summary -->
    <tr>
      <td style="padding:{estate_padding};">
        <h2 style="font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#111827;
                   margin:0 0 12px 0;padding-bottom:8px;border-bottom:2px solid #e5e7eb;">
          Estate Summary
        </h2>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
          {estate_rows_html}
        </table>
      </td>
    </tr>

    {leaderboard_block}

    <!-- Footer -->
    <tr>
      <td style="background-color:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">
        <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#9ca3af;">
          Report generated {now_str} &middot; Defense Halo Customer CVE Analyzer
        </p>
      </td>
    </tr>

  </table>

</td></tr>
</table>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Plain-text fallback
# ---------------------------------------------------------------------------

def _build_plain(estate_stats: dict, leaderboard: list, preamble_html: str) -> str:
    e = estate_stats
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
            score = float(row.get("max_score") or 0.0)
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

    # ── Outer: mixed (carries the attachment) ──────────────────────────────
    msg = MIMEMultipart("mixed")
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)
    msg["Subject"] = subject
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)

    # ── Inner: alternative (plain-text + HTML) ─────────────────────────────
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(plain_body, "plain", "utf-8"))
    alt.attach(MIMEText(html_body,  "html",  "utf-8"))
    msg.attach(alt)

    # ── Excel attachment ───────────────────────────────────────────────────
    fname = f"cve_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    attachment = MIMEApplication(
        xlsx_bytes,
        Name=fname,
        _subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    attachment["Content-Disposition"] = f'attachment; filename="{fname}"'
    msg.attach(attachment)

    # ── SMTP delivery ──────────────────────────────────────────────────────
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
