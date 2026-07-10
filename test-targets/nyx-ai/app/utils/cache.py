"""Redis-backed response cache for LLM completions.

Caching identical prompts avoids redundant upstream API calls and reduces
p99 latency for repeated queries.  Cache keys are SHA-256 hashes of the
(model, prompt, temperature) tuple so collisions are not a concern.
"""

from __future__ import annotations

import hashlib
import pickle
from typing import Any, Optional

import redis
import structlog

from ..config import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()

_client: Optional[redis.Redis] = None


def _redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(settings.redis_url, decode_responses=False)
    return _client


def cache_key(model: str, prompt: str, temperature: float) -> str:
    raw = f"{model}:{prompt}:{temperature}"
    return "nyx:completion:" + hashlib.sha256(raw.encode()).hexdigest()


def get_cached_completion(model: str, prompt: str, temperature: float) -> Optional[Any]:
    """Return a cached completion dict, or None on cache miss."""
    key = cache_key(model, prompt, temperature)
    try:
        data = _redis().get(key)
        if data is None:
            return None
        return pickle.loads(data)
    except Exception as exc:
        log.warning("cache.get_error", key=key, error=str(exc))
        return None


def set_cached_completion(
    model: str,
    prompt: str,
    temperature: float,
    result: Any,
    ttl: int | None = None,
) -> None:
    """Serialise *result* and write it to Redis with an optional TTL."""
    key = cache_key(model, prompt, temperature)
    ttl = ttl if ttl is not None else settings.cache_ttl_seconds
    try:
        _redis().setex(key, ttl, pickle.dumps(result))
        log.debug("cache.set", key=key, ttl=ttl)
    except Exception as exc:
        log.warning("cache.set_error", key=key, error=str(exc))
