"""Origin email service.

Providers: SMTP, AWS SES, SendGrid, Resend, Gmail. Configured through Origin's
`platform_settings` cache.
"""

from __future__ import annotations

import base64
import html
import logging
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from email.utils import formataddr, formatdate, make_msgid
from typing import Optional

import aiosmtplib
import httpx

from origin import config
from origin.services.platform_settings_service import settings

logger = logging.getLogger(__name__)

# Gmail (OAuth2) endpoints — the `gmail` provider reuses the platform's Google
# OAuth app to send via the Gmail API on behalf of the sending mailbox.
_GMAIL_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


def _provider() -> str:
    """Active email provider. DB-backed setting wins; ``EMAIL_PROVIDER`` env is
    the first-boot fallback (same precedence the rest of the platform uses)."""
    return (settings.get("email.provider") or os.getenv("EMAIL_PROVIDER", "") or "").strip().lower()


def _from_address() -> str:
    return settings.get("email.from_address") or os.getenv("PLATFORM_EMAIL_ADDRESS", "") or ""


def _gmail_config() -> dict:
    """Resolve the Gmail OAuth2 credentials for the platform email SENDER — a
    DEDICATED Google OAuth client, independent of Google sign-in. Precedence
    (first non-empty wins), matching the rest of the platform:
      1. DB settings ``email.gmail.*`` (wizard / static seed)
      2. ``GMAIL_OAUTH_*`` env (unattended / .env first-boot)
      3. the sign-in app ``auth.google.*`` / ``GOOGLE_OAUTH_*`` (backward-compat)
    A refresh token for the sending mailbox is required to mint Gmail API tokens."""
    return {
        "client_id": settings.get("email.gmail.client_id")
        or os.getenv("GMAIL_OAUTH_CLIENT_ID", "")
        or settings.get("auth.google.client_id")
        or os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
        or "",
        "client_secret": settings.get_secret("email.gmail.client_secret")
        or os.getenv("GMAIL_OAUTH_CLIENT_SECRET", "")
        or settings.get_secret("auth.google.client_secret")
        or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
        or "",
        "refresh_token": settings.get_secret("email.gmail.refresh_token")
        or os.getenv("GMAIL_OAUTH_REFRESH_TOKEN", "")
        or settings.get_secret("auth.google.refresh_token")
        or os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN", "")
        or "",
    }


def _get_provider_config() -> dict:
    return {
        "provider": _provider(),
        "from_address": _from_address(),
        "from_name": settings.get("email.from_name", "Agience"),
        "reply_to": settings.get("email.reply_to", "") or "",
        "smtp_host": settings.get("email.smtp.host", ""),
        "smtp_port": settings.get_int("email.smtp.port", 587),
        # username / access_key_id are stored as plain settings by both writers
        # (setup wizard + manifest classify only password/secret/api_key/token/
        # credential as secret). Read them with get(), not get_secret(), or they
        # come back empty and SMTP/SES auth silently fails.
        "smtp_username": settings.get("email.smtp.username", "") or "",
        "smtp_password": settings.get_secret("email.smtp.password") or "",
        "smtp_use_tls": settings.get_bool("email.smtp.use_tls", True),
        "ses_region": settings.get("email.ses.region", "us-east-1"),
        "ses_access_key_id": settings.get("email.ses.access_key_id", "") or "",
        "ses_secret_access_key": settings.get_secret("email.ses.secret_access_key") or "",
        "sendgrid_api_key": settings.get_secret("email.sendgrid.api_key") or "",
        "resend_api_key": settings.get_secret("email.resend.api_key") or "",
    }


def is_configured() -> bool:
    provider = _provider()
    if provider == "gmail":
        # Gmail validates against the Google OAuth app: it needs the client
        # credentials plus a refresh token for the sending mailbox.
        gm = _gmail_config()
        return bool(gm["client_id"] and gm["client_secret"] and gm["refresh_token"])
    return provider in {"smtp", "ses", "sendgrid", "resend"}


async def send_email(
    to_email: str, subject: str, html_body: str, text_body: Optional[str] = None
) -> bool:
    cfg = _get_provider_config()
    provider = cfg["provider"]
    if not provider:
        logger.warning("Email not configured — cannot send to %s", to_email)
        return False
    try:
        if provider == "smtp":
            return await _send_smtp(cfg, to_email, subject, html_body, text_body)
        if provider == "ses":
            return await _send_ses(cfg, to_email, subject, html_body, text_body)
        if provider == "sendgrid":
            return await _send_sendgrid(cfg, to_email, subject, html_body, text_body)
        if provider == "resend":
            return await _send_resend(cfg, to_email, subject, html_body, text_body)
        if provider == "gmail":
            return await _send_gmail(cfg, to_email, subject, html_body, text_body)
        logger.error("Unknown email provider: %s", provider)
        return False
    except Exception:
        logger.exception("Failed to send email to %s via %s", to_email, provider)
        return False


def _platform() -> str:
    return settings.get("branding.title", "Agience")


_BROWSERS = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
             ("CriOS/", "Chrome"), ("Safari/", "Safari"))
_SYSTEMS = (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Windows", "Windows"),
            ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux"))


def request_context(user_agent: Optional[str], at: Optional[datetime] = None) -> str:
    """One sentence saying when and from what a mail was asked for, so its recipient can tell
    whether it was them: "Requested on 11 Oct 2026 at 15:48 UTC from Chrome on Windows." Only names
    from a fixed list are used: nothing the caller wrote is copied into the mail."""
    ua = user_agent or ""
    browser = next((name for mark, name in _BROWSERS if mark in ua), "a web browser")
    system = next((name for mark, name in _SYSTEMS if mark in ua), "")
    when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return (f"Requested on {when.day} {when:%b %Y} at {when:%H:%M} UTC from {browser}"
            + (f" on {system}." if system else "."))


def _context_html(context: str) -> str:
    return f'<p style="color:#777;font-size:13px;">{html.escape(context)}</p>' if context else ""


def _logo_url() -> str:
    """The logo at the top of every message: `branding.email_logo_url`, else the 320 px copy this
    Origin serves itself (`web/logo_mail.png`). A mail client shows only an image at a public URL."""
    return (settings.get("branding.email_logo_url")
            or f"{str(config.AUTHORITY_ISSUER).rstrip('/')}/web/logo_mail.png")


def _document(title: str, preview: str, inner: str) -> str:
    """A whole HTML document around one message: doctype, language, charset, title, a preview line
    (what a mail client shows beside the subject), the logo, and a footer saying who sent it and
    why. A bare fragment holding one button is what phishing looks like to a junk filter."""
    platform = html.escape(_platform())
    logo = (f'<img src="{html.escape(_logo_url(), quote=True)}" alt="{platform}" width="160" height="40" '
            'style="display:block;border:0;margin:0 0 24px;">')
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title></head>"
        '<body style="margin:0;padding:24px;background:#ffffff;font-family:system-ui,sans-serif;color:#1a1a1a;">'
        f'<div style="display:none;max-height:0;overflow:hidden;">{html.escape(preview)}</div>'
        f'<div style="max-width:480px;margin:0 auto;">{logo}{inner}'
        '<hr style="border:none;border-top:1px solid #eee;margin:32px 0 16px;">'
        f'<p style="color:#999;font-size:12px;">This message was sent by {platform} because this address '
        "was used on its sign-in page. Replies reach a person.</p>"
        "</div></body></html>"
    )


def _button(url: str, label: str) -> str:
    return (f'<a href="{html.escape(url, quote=True)}" style="display:inline-block;background:#1a1a1a;'
            'color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;margin:20px 0;">'
            f"{html.escape(label)}</a>")


async def send_otp(to_email: str, code: str, context: str = "") -> bool:
    platform = _platform()
    subject = f"Your {platform} sign-in code"
    inner = (
        '<h2 style="margin:0 0 12px;">Your sign-in code</h2>'
        f'<p style="color:#555;font-size:14px;">Enter this code to sign in to {html.escape(platform)} '
        f"as {html.escape(to_email)}:</p>"
        '<div style="background:#f5f5f5;border-radius:8px;padding:20px;text-align:center;margin:20px 0;">'
        f'<span style="font-size:32px;font-weight:bold;letter-spacing:8px;">{html.escape(code)}</span></div>'
        '<p style="color:#777;font-size:13px;">The code expires in 10 minutes. If you did not ask to sign in, '
        "you can ignore this message; nobody can sign in without the code.</p>"
        + _context_html(context)
    )
    text = (f"Your {platform} sign-in code for {to_email} is: {code}\n\n"
            "The code expires in 10 minutes. If you did not ask to sign in, you can ignore this "
            "message; nobody can sign in without the code.\n" + (f"\n{context}\n" if context else ""))
    return await send_email(to_email, subject, _document(subject, f"Your code is {code}", inner), text)


async def send_password_reset(to_email: str, reset_url: str, context: str = "") -> bool:
    platform = _platform()
    subject = f"Reset your {platform} password"
    inner = (
        '<h2 style="margin:0 0 12px;">Reset your password</h2>'
        f'<p style="color:#555;font-size:14px;">Someone asked to reset the {html.escape(platform)} password '
        f"for {html.escape(to_email)}. To choose a new one, open this link:</p>"
        + _button(reset_url, "Choose a new password")
        + '<p style="color:#777;font-size:13px;">The link works once and expires in 1 hour. If you did not '
        "ask for this, ignore this message: your password stays as it is.</p>"
        + _context_html(context)
    )
    text = (f"Someone asked to reset the {platform} password for {to_email}.\n\n"
            f"To choose a new one, open this link:\n{reset_url}\n\n"
            "The link works once and expires in 1 hour. If you did not ask for this, ignore this "
            "message: your password stays as it is.\n" + (f"\n{context}\n" if context else ""))
    return await send_email(to_email, subject,
                            _document(subject, "Choose a new password for your account", inner), text)


async def send_email_verification(to_email: str, verify_url: str, context: str = "") -> bool:
    platform = _platform()
    subject = f"Confirm your email for {platform}"
    inner = (
        '<h2 style="margin:0 0 12px;">Confirm your email</h2>'
        f'<p style="color:#555;font-size:14px;">To finish setting up your {html.escape(platform)} account '
        f"for {html.escape(to_email)}, confirm this address:</p>"
        + _button(verify_url, "Confirm email")
        + '<p style="color:#777;font-size:13px;">The link expires in 24 hours. If you did not create an '
        "account, ignore this message and nothing is set up.</p>"
        + _context_html(context)
    )
    text = (f"To finish setting up your {platform} account for {to_email}, confirm this address:\n"
            f"{verify_url}\n\nThe link expires in 24 hours. If you did not create an account, "
            "ignore this message and nothing is set up.\n" + (f"\n{context}\n" if context else ""))
    return await send_email(to_email, subject,
                            _document(subject, "One step left to finish your account", inner), text)


async def send_invite(
    to_email: str,
    from_name: str,
    resource_name: str,
    claim_url: str,
    message: Optional[str] = None,
) -> bool:
    platform = _platform()
    subject = f"{from_name} invited you to collaborate on {platform}"
    note = (f'<p style="color:#444;font-size:14px;margin:16px 0;padding:12px;background:#f9f9f9;'
            f'border-radius:6px;">&ldquo;{html.escape(message)}&rdquo;</p>') if message else ""
    inner = (
        '<h2 style="margin:0 0 12px;">You&rsquo;ve been invited</h2>'
        f'<p style="color:#555;font-size:14px;"><strong>{html.escape(from_name)}</strong> invited you to '
        f"<strong>{html.escape(resource_name)}</strong> on {html.escape(platform)}.</p>"
        + note + _button(claim_url, f"View in {platform}")
        + '<p style="color:#777;font-size:13px;">If you do not have an account yet, one is created when '
        "you sign in.</p>"
    )
    text = (f"{from_name} invited you to {resource_name} on {platform}.\n"
            + (f'\n"{message}"\n' if message else "")
            + f"\nOpen this link to accept:\n{claim_url}\n\n"
            "If you do not have an account yet, one is created when you sign in.\n")
    return await send_email(to_email, subject,
                            _document(subject, f"{from_name} invited you to {resource_name}", inner), text)


async def test_connection(provider_config: dict) -> tuple[bool, Optional[str]]:
    provider = provider_config.get("provider", "")
    try:
        if provider == "smtp":
            smtp = aiosmtplib.SMTP(
                hostname=provider_config.get("smtp_host", ""),
                port=int(provider_config.get("smtp_port", 587)),
                use_tls=provider_config.get("smtp_use_tls", True),
            )
            await smtp.connect()
            if provider_config.get("smtp_username"):
                await smtp.login(
                    provider_config["smtp_username"],
                    provider_config.get("smtp_password", ""),
                )
            await smtp.quit()
            return True, None
        if provider == "sendgrid":
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.sendgrid.com/v3/scopes",
                    headers={"Authorization": f"Bearer {provider_config.get('sendgrid_api_key', '')}"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    return True, None
                return False, f"SendGrid API returned {resp.status_code}"
        if provider == "resend":
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.resend.com/domains",
                    headers={"Authorization": f"Bearer {provider_config.get('resend_api_key', '')}"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    return True, None
                return False, f"Resend API returned {resp.status_code}"
        if provider == "ses":
            import boto3

            ses = boto3.client(
                "ses",
                region_name=provider_config.get("ses_region", "us-east-1"),
                aws_access_key_id=provider_config.get("ses_access_key_id", ""),
                aws_secret_access_key=provider_config.get("ses_secret_access_key", ""),
            )
            ses.get_send_quota()
            return True, None
        if provider == "gmail":
            # Success = the Gmail OAuth app can mint a Gmail access token from the
            # refresh token. Ignores inbound config; reads GMAIL_OAUTH_* (falls
            # back to GOOGLE_OAUTH_*).
            await _gmail_access_token(_gmail_config())
            return True, None
        return False, f"Unknown provider: {provider}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------
def _mime(cfg: dict, to: str, subject: str, html_body: str, text: Optional[str]) -> MIMEMultipart:
    """The message SMTP and Gmail send: plain text first, then HTML, with the headers a receiving
    filter expects of real mail (`Date`, a `Message-ID` on the sender's own domain, `Reply-To`)."""
    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((cfg["from_name"], cfg["from_address"]))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Reply-To"] = cfg.get("reply_to") or cfg["from_address"]
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=cfg["from_address"].rpartition("@")[2] or None)
    if text:
        msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


async def _send_smtp(cfg: dict, to: str, subject: str, html: str, text: Optional[str]) -> bool:
    msg = _mime(cfg, to, subject, html, text)
    smtp = aiosmtplib.SMTP(
        hostname=cfg["smtp_host"], port=cfg["smtp_port"], use_tls=cfg["smtp_use_tls"]
    )
    await smtp.connect()
    if cfg["smtp_username"]:
        await smtp.login(cfg["smtp_username"], cfg["smtp_password"])
    await smtp.send_message(msg)
    await smtp.quit()
    logger.info("Email sent via SMTP to %s", to)
    return True


async def _send_ses(cfg: dict, to: str, subject: str, html: str, text: Optional[str]) -> bool:
    import boto3

    ses = boto3.client(
        "ses",
        region_name=cfg["ses_region"],
        aws_access_key_id=cfg["ses_access_key_id"],
        aws_secret_access_key=cfg["ses_secret_access_key"],
    )
    body = {"Html": {"Data": html}}
    if text:
        body["Text"] = {"Data": text}
    ses.send_email(
        Source=f"{cfg['from_name']} <{cfg['from_address']}>",
        Destination={"ToAddresses": [to]},
        Message={"Subject": {"Data": subject}, "Body": body},
    )
    logger.info("Email sent via SES to %s", to)
    return True


async def _send_sendgrid(cfg: dict, to: str, subject: str, html: str, text: Optional[str]) -> bool:
    content = [{"type": "text/html", "value": html}]
    if text:
        content.insert(0, {"type": "text/plain", "value": text})
    payload = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": cfg["from_address"], "name": cfg["from_name"]},
        "subject": subject,
        "content": content,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={
                "Authorization": f"Bearer {cfg['sendgrid_api_key']}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
    logger.info("Email sent via SendGrid to %s", to)
    return True


async def _send_resend(cfg: dict, to: str, subject: str, html: str, text: Optional[str]) -> bool:
    payload = {
        "from": f"{cfg['from_name']} <{cfg['from_address']}>",
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            json=payload,
            headers={
                "Authorization": f"Bearer {cfg['resend_api_key']}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
    logger.info("Email sent via Resend to %s", to)
    return True


async def _gmail_access_token(gm: dict) -> str:
    """Exchange the long-lived refresh token for a short-lived Gmail access
    token via Google's OAuth2 token endpoint."""
    if not (gm["client_id"] and gm["client_secret"] and gm["refresh_token"]):
        raise ValueError(
            "Gmail provider requires GMAIL_OAUTH client_id, client_secret, and refresh_token"
        )
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _GMAIL_TOKEN_URL,
            data={
                "client_id": gm["client_id"],
                "client_secret": gm["client_secret"],
                "refresh_token": gm["refresh_token"],
                "grant_type": "refresh_token",
            },
            timeout=15,
        )
        resp.raise_for_status()
        token = (resp.json() or {}).get("access_token")
    if not token:
        raise ValueError("Gmail token exchange returned no access_token")
    return token


async def _send_gmail(cfg: dict, to: str, subject: str, html: str, text: Optional[str]) -> bool:
    access_token = await _gmail_access_token(_gmail_config())
    msg = _mime(cfg, to, subject, html, text)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _GMAIL_SEND_URL,
            json={"raw": raw},
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
    logger.info("Email sent via Gmail to %s", to)
    return True
