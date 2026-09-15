"""A content-addressed cache in front of any gateway.

This wrapper is what makes an adjudicated run *reproducible*, which matters
more here than the cost saving. The project's central claim is that its results
are a property of the program analysis; a layer whose answers change between
two runs over the same source would undermine that claim on the first re-run a
reviewer tried. Keying on the exact bytes sent means identical input yields the
identical verdict, and a changed slice -- because the code changed -- correctly
misses the cache.

Entries are plain JSON files. A corrupt or unreadable entry is treated as a
miss rather than an error: a cache that can break a build is worse than no
cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from .base import GatewayResponse, ModelGateway

#: Bumped when the stored shape changes, so old entries are ignored rather
#: than misread.
CACHE_VERSION = 1


def cache_key(
    model: str,
    system: str,
    user: str,
    schema: dict | None,
    temperature: float,
    variant: str = "",
) -> str:
    """A digest over everything that can change an answer.

    ``variant`` carries request settings that live on the gateway rather than
    in the prompt -- reasoning effort, the fallback chain. Two roles asking the
    same model the same question at different effort can reach different
    verdicts, so they must not share an entry. It is omitted from the digest
    when empty, so entries written before it existed stay valid.
    """
    digest = hashlib.sha256()
    digest.update(f"v{CACHE_VERSION}\0{model}\0{temperature:.4f}\0".encode())
    if variant:
        digest.update(f"variant\0{variant}\0".encode())
    digest.update(system.encode("utf-8", errors="replace"))
    digest.update(b"\0")
    digest.update(user.encode("utf-8", errors="replace"))
    digest.update(b"\0")
    digest.update(json.dumps(schema, sort_keys=True).encode() if schema else b"-")
    return digest.hexdigest()


class CachingGateway:
    """Wraps a gateway, serving repeats from disk."""

    def __init__(
        self,
        inner: ModelGateway,
        directory: Path,
        ttl_seconds: float | None = None,
    ) -> None:
        self.inner = inner
        self.directory = Path(directory)
        self.ttl_seconds = ttl_seconds
        self.hits = 0
        self.misses = 0
        self.writes = 0

    @property
    def model_id(self) -> str:
        return self.inner.model_id

    @property
    def available(self) -> bool:
        return self.inner.available

    def complete(
        self,
        system: str,
        user: str,
        schema: dict | None = None,
        temperature: float = 0.0,
    ) -> GatewayResponse:
        key = cache_key(self.model_id, system, user, schema, temperature, self._variant())
        cached = self._read(key)
        if cached is not None:
            self.hits += 1
            return cached

        self.misses += 1
        response = self.inner.complete(system, user, schema=schema, temperature=temperature)
        self._write(key, response)
        return response

    def _variant(self) -> str:
        """Gateway settings that change an answer without appearing in the prompt."""
        effort = getattr(self.inner, "reasoning_effort", "") or ""
        fallbacks = getattr(self.inner, "fallback_models", ()) or ()
        parts = []
        if effort:
            parts.append(f"effort={effort}")
        if fallbacks:
            parts.append("fallbacks=" + ",".join(fallbacks))
        return ";".join(parts)

    # -- storage ------------------------------------------------------------

    def _path(self, key: str) -> Path:
        # Two-character shard: a large audit can produce thousands of entries,
        # and some file systems degrade badly on a single flat directory.
        return self.directory / key[:2] / f"{key}.json"

    def _read(self, key: str) -> GatewayResponse | None:
        path = self._path(key)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if payload.get("version") != CACHE_VERSION:
            return None
        if self.ttl_seconds is not None:
            age = time.time() - float(payload.get("stored_at", 0))
            if age > self.ttl_seconds:
                return None
        return GatewayResponse(
            data=payload.get("data", {}),
            model=payload.get("model", self.model_id),
            cached=True,
            latency_ms=0.0,
            raw=payload.get("raw", ""),
            usage=payload.get("usage", {}),
        )

    def _write(self, key: str, response: GatewayResponse) -> None:
        path = self._path(key)
        payload = {
            "version": CACHE_VERSION,
            "stored_at": time.time(),
            "model": response.model,
            "data": response.data,
            "raw": response.raw,
            "usage": response.usage,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Written through a temporary file and renamed: two audits running
            # concurrently must never leave a half-written entry behind, and a
            # truncated JSON file would be read as a miss forever after.
            handle, temporary = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream)
            os.replace(temporary, path)
            self.writes += 1
        except OSError:
            # An unwritable cache directory is not a reason to fail an audit.
            pass

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }
