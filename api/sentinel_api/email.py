from __future__ import annotations

import os

import httpx
import structlog

log = structlog.get_logger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"


async def _send(to: str, subject: str, text: str) -> None:
    """Send via Resend if RESEND_API_KEY is configured; otherwise log the content.

    This mirrors how the rest of Sentinel handles optional external providers
    (e.g. the LLM provider config) — works out of the box locally/self-hosted
    with no credentials, upgrades to real delivery once configured.
    """
    api_key = os.getenv("RESEND_API_KEY")
    from_address = os.getenv("EMAIL_FROM", "Sentinel <onboarding@resend.dev>")

    if not api_key:
        log.info("email.not_configured", to=to, subject=subject, body=text)
        return

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            RESEND_API_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"from": from_address, "to": [to], "subject": subject, "text": text},
        )
        if response.status_code >= 400:
            log.error("email.send_failed", to=to, subject=subject, status_code=response.status_code, body=response.text)


async def send_verification_email(to: str, link: str) -> None:
    await _send(
        to,
        subject="Verify your Sentinel email",
        text=f"Confirm your email address to finish setting up Sentinel:\n\n{link}\n\nThis link expires in 24 hours.",
    )


async def send_password_reset_email(to: str, link: str) -> None:
    await _send(
        to,
        subject="Reset your Sentinel password",
        text=f"Reset your password:\n\n{link}\n\nThis link expires in 1 hour. If you didn't request this, you can ignore this email.",
    )
