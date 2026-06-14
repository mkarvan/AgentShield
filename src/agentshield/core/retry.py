"""Simple exponential-backoff retry for async HTTP calls."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx

logger = logging.getLogger(__name__)

T = TypeVar("T")

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_BASE_DELAY = 1.0  # seconds
_MAX_DELAY = 30.0


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int = _MAX_RETRIES,
    base_delay: float = _BASE_DELAY,
    max_delay: float = _MAX_DELAY,
    label: str = "HTTP request",
) -> T:
    """Call *fn* with exponential backoff on retryable HTTP errors.

    Retries on ``httpx.HTTPStatusError`` with status 429/5xx and on
    transient connection errors (``httpx.TransportError``).
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in _RETRYABLE_STATUS_CODES:
                raise
            last_exc = exc
        except httpx.TransportError as exc:
            last_exc = exc

        if attempt < max_retries:
            delay = min(base_delay * (2**attempt) + random.uniform(0, 1), max_delay)
            logger.debug(
                "%s: attempt %d failed, retrying in %.1fs — %s",
                label,
                attempt + 1,
                delay,
                last_exc,
            )
            await asyncio.sleep(delay)

    assert last_exc is not None  # noqa: S101
    raise last_exc
