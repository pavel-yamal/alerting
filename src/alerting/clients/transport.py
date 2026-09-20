"""HTTP and WebSocket plumbing for the CLIs."""

from __future__ import annotations

from typing import Any

import httpx


class ServerError(RuntimeError):
    pass


class Api:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)

    @property
    def ws_url(self) -> str:
        return self.base_url.replace("https://", "wss://").replace("http://", "ws://")

    def get(self, path: str, **params: Any) -> Any:
        response = self._client.get(path, params=params or None)
        return self._unwrap(response)

    def post(self, path: str, body: Any = None) -> Any:
        response = self._client.post(path, json=body)
        return self._unwrap(response)

    @staticmethod
    def _unwrap(response: httpx.Response) -> Any:
        if response.status_code >= 400:
            raise ServerError(f"{response.status_code}: {response.text}")
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Api:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
