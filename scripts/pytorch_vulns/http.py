from typing import Any

import httpx
from httpx_retries import Retry, RetryTransport


class ApiClient:
    def __init__(self) -> None:
        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"},
        )
        self.client = httpx.Client(
            transport=RetryTransport(retry=retry),
            timeout=45,
            headers={"User-Agent": "pytorch-vulnerability-coursework/1.0", "Accept": "application/json"},
        )

    def close(self) -> None:
        self.client.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        response = self.client.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs).json()

    def post_json(self, url: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", url, json=payload).json()
