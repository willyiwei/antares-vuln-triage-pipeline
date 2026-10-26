"""Cisco AnTAres API client — abstracts scan submission and result retrieval."""

from __future__ import annotations

import time
from typing import Any

import httpx
from httpx import HTTPStatusError, TimeoutException

from .config import AnTAresConfig
from .models import ScanResult, VulnerabilityFinding, Severity, FindingStatus


class AnTAresClientError(Exception):
    """Base exception for AnTAres client errors."""


class AnTAresClient:
    """HTTP client for the Cisco AnTAres API with retry and rate limiting."""

    def __init__(self, config: AnTAresConfig | None = None) -> None:
        self.config = config or AnTAresConfig()
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url.rstrip("/"),
            timeout=httpx.Timeout(self.config.timeout_seconds),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "antares-vuln-triage/0.1.0",
            },
        )
        self._last_request_at: float = 0.0

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AnTAresClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def health_check(self) -> dict[str, Any]:
        """Verify connectivity to the AnTAres API."""
        try:
            resp = await self._client.get("/health", timeout=10)
            resp.raise_for_status()
            return {"status": "ok", "version": resp.json().get("version", "unknown")}
        except (HTTPStatusError, TimeoutException, ConnectionError) as e:
            raise AnTAresClientError(f"Health check failed: {e}") from e

    async def submit_scan(
        self,
        repo_url: str,
        branch: str | None = None,
        commit_sha: str | None = None,
        scan_type: str = "full",
    ) -> dict[str, Any]:
        """Submit a repository scan to AnTAres and return the scan job ID."""
        await self._rate_limit()
        payload: dict[str, Any] = {"repo_url": repo_url, "scan_type": scan_type}
        if branch:
            payload["branch"] = branch
        if commit_sha:
            payload["commit_sha"] = commit_sha

        try:
            resp = await self._client.post("/scans", json=payload)
            resp.raise_for_status()
            return resp.json()
        except HTTPStatusError as e:
            raise AnTAresClientError(f"Scan submission failed ({e.response.status_code}): {e.response.text}") from e

    async def get_scan_results(self, scan_id: str, wait: bool = False, poll_interval: int = 5) -> dict[str, Any]:
        """Retrieve scan results by ID, optionally polling until complete."""
        if wait:
            while True:
                await self._rate_limit()
                resp = await self._client.get(f"/scans/{scan_id}")
                resp.raise_for_status()
                data = resp.json()
                status = data.get("status", "unknown")
                if status in ("completed", "failed", "cancelled"):
                    break
                await asyncio.sleep(poll_interval)
        else:
            await self._rate_limit()
            resp = await self._client.get(f"/scans/{scan_id}")
            resp.raise_for_status()
            data = resp.json()

        return data

    async def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch individual findings for a completed scan."""
        await self._rate_limit()
        resp = await self._client.get(f"/scans/{scan_id}/findings")
        resp.raise_for_status()
        return resp.json().get("findings", [])

    def _rate_limit(self) -> None:
        """Simple token-bucket rate limiter."""
        interval = 60.0 / max(self.config.rate_limit_per_minute, 1)
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request_at = time.monotonic()

    async def close_sync(self) -> None:
        """Synchronous close for non-async contexts."""
        await self.close()


# Import asyncio at module level for the wait/poll path
import asyncio  # noqa: E402
