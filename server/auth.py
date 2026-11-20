"""API-key authentication for the server.

The key comes from PHISH_API_KEY in .env. When no key is configured the
check is skipped with a warning (local development only).
"""
import logging

from fastapi import Header, HTTPException

from .config import settings

logger = logging.getLogger(__name__)


def verify_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    """FastAPI dependency: require the configured X-API-Key header."""
    if not settings.api_key:
        logger.warning("PHISH_API_KEY is not set; API key check is disabled")
        return True
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True
