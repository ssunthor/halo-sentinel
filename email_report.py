"""
Email report sender for the Defense Halo CVE Analyzer.

send_report_email() is the sole public entry point. It:
  1. Builds a plain-text email with an optional auto-generated stats block
     appended after the operator's preamble.
  2. Attaches the pre-built Excel workbook.
  3. Delivers via SMTP with configurable TLS mode and optional credentials.

All arguments come from the caller (main.py) so this module has no FastAPI
or asyncio dependencies and can be called from a thread executor.
"""

import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional


# ---------------------------------------------------------------------------
# Stats block builder
# ---------------------------------------------------------------------------

def _build_stats_block(estate_stats: dict, leaderboard: list) -> str:
    """Return a plain-text stats summary to append after the preamble."""
    e = estate_stats
    lines = [
        "=" * 60,
        "ESTATE SUMMARY",
        "=" * 60,
        f"  Clients scanned     : {e.get('total_tenants', 0):,}",
        f"  Total devices       : {e.get('total_devices', 0):,}",
        f"  Vulnerable devices  : {e.get('vulnerable_devices', 0):,}"
        + (f" ({round(100 * e.get('vulnerable_devices', 0) / e['total_devices'])}% of estate)"
           if e.get('total_devices') else ""),
        f"  Critical (≥ 9.0)    : {e.get('critical_devices', 0):,}",
        f"  Total CVE instances : {e.get('total_cve_instances', 0):,}",
        f"  Peak CVE score      : {(e.get('max_score') or 0.0):.1f}",
        "",
    ]

    if leaderboard:
        lines += [
            "TOP 10 CLIENTS BY CVE SCORE",
            "-" * 60,
        ]
        for i, row in enumerate(leaderboard[:10], 1):
            score = (row.get("max_score") or 0.0)
            vuln  = row.get("vulnerable_devices", 0)
            total = row.get("total_devices", 0)
            lines.append(
                f"  {i:2}. {row.get('name', '—'):<35} "
                f"Score: {score:4.1f}   Vuln: {vuln}/{total}"
            )
        lines.append("")

    lines += [
        "=" * 60,
        f"Report generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 60,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subject token substitution
# ---------------------------------------------------------------------------

def _render_subject(template: str, estate_stats: dict) -> str:
    e = estate_stats
    now = datetime.now(timezone.utc)
    return (
        template
        .replace("{date}",             now.strftime("%Y-%m-%d"))
        .replace("{datetime}",         now.strftime("%Y-%m-%d %H:%M UTC"))
        .replace("{total_clients}",    str(e.get("total_tenants", 0)))
        .replace("{vulnerable}",       str(e.get("vulnerable_devices", 0)))
        .replace("{critical}",         str(e.get("critical_devices", 0)))
        .replace("{peak_score}",       f"{(e.get('max_score') or 0.0):.1f}")
    )


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
    Build and deliver the CVE report email.

    Raises an exception on any SMTP or configuration error — callers should
    catch and surface the message to the operator.

    config keys used:
        smtp_host, smtp_port, smtp_tls ("none"|"starttls"|"tls"),
        smtp_username, smtp_password,
        from_address, to_addresses, cc_addresses, bcc_addresses,
        subject, body_preamble
    """
    smtp_host = config.get("smtp_host", "").strip()
    smtp_port = int(config.get("smtp_port") or 587)
    tls_mode  = (config.get("smtp_tls") or "starttls").lower()
    username  = config.get("smtp_username", "").strip()
    password  = config.get("smtp_password", "")

    from_addr  = config.get("from_address", "").strip()
    to_addrs   = [a.strip() for a in (config.get("to_addresses")  or []) if a.strip()]
    cc_addrs   = [a.strip() for a in (config.get("cc_addresses")  or []) if a.strip()]
    bcc_addrs  = [a.strip() for a in (config.get("bcc_addresses") or []) if a.strip()]

    if not smtp_host:
        raise ValueError("SMTP host is not configured.")
    if not from_addr:
        raise ValueError("From address is not configured.")
    if not to_addrs:
        raise ValueError("No To recipients configured.")

    all_rcpt = to_addrs + cc_addrs + bcc_addrs

    # ── Build message body ──────────────────────────────────────────────────
    preamble = (config.get("body_preamble") or "").strip()
    stats_block = _build_stats_block(estate_stats, leaderboard)
    body = "\n\n".join(filter(None, [preamble, stats_block]))

    subject = _render_subject(
        config.get("subject") or "Defense Halo CVE Report — {date}",
        estate_stats,
    )

    # ── Assemble MIME message ───────────────────────────────────────────────
    msg = MIMEMultipart()
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)
    msg["Subject"] = subject
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)

    msg.attach(MIMEText(body, "plain", "utf-8"))

    fname = f"cve_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    attachment = MIMEApplication(
        xlsx_bytes,
        Name=fname,
        _subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    attachment["Content-Disposition"] = f'attachment; filename="{fname}"'
    msg.attach(attachment)

    # ── SMTP delivery ───────────────────────────────────────────────────────
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
