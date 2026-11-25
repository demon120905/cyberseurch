"""Потокобезопасный HTTP-клиент для сети TRON (TronGrid / FullNode API) с rate-limit и retry."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional


class TronAPIClient:
    """Клиент для получения транзакций и подписей TRON через TronGrid / FullNode HTTP API."""

    DEFAULT_ENDPOINT = "https://api.trongrid.io"

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        api_key: str = "",
        rate_limit: int = 8,
        timeout: int = 20,
        logger: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.endpoint = (endpoint.strip() or self.DEFAULT_ENDPOINT).rstrip("/")
        self.api_key = api_key.strip()
        self.requests_per_second = max(1, int(rate_limit))
        self.timeout = timeout
        self._logger = logger

        self._rate_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._request_times: Deque[float] = deque()

        self.total_requests = 0
        self.failed_requests = 0
        self.retry_count = 0

    def _log(self, level: str, msg: str) -> None:
        if self._logger:
            self._logger(level, msg)

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ECDSA-CyberScanner/3.1",
        }
        if self.api_key:
            headers["TRON-PRO-API-KEY"] = self.api_key
        return headers

    def enforce_rate_limit(self) -> None:
        with self._rate_lock:
            now = time.monotonic()
            while self._request_times and (now - self._request_times[0]) >= 1.0:
                self._request_times.popleft()
            if len(self._request_times) >= self.requests_per_second:
                sleep_for = 1.0 - (now - self._request_times[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.monotonic()
                while self._request_times and (now - self._request_times[0]) >= 1.0:
                    self._request_times.popleft()
            self._request_times.append(time.monotonic())

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        url = f"{self.endpoint}{path}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = self._build_headers()

        retry = 0
        backoff = 0.5
        last_error: Optional[Exception] = None

        while retry <= max_retries:
            try:
                self.enforce_rate_limit()
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                with self._stats_lock:
                    self.total_requests += 1
                if not raw.strip():
                    return {}
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {"data": parsed}

            except urllib.error.HTTPError as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                err_text = ""
                try:
                    err_text = exc.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass
                last_error = RuntimeError(f"HTTP {exc.code}: {exc.reason} {err_text}".strip())
                if exc.code == 429:
                    backoff = max(backoff, 2.0)
                elif exc.code in (400, 401, 403, 404):
                    raise last_error from exc
            except Exception as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                last_error = exc

            if retry < max_retries:
                self._log("WARNING", f"Повтор TRON API ({retry + 1}/{max_retries}): {last_error}")
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 6.0)
                with self._stats_lock:
                    self.retry_count += 1
            retry += 1

        raise RuntimeError(f"TRON API недоступен после {max_retries} попыток: {last_error}")

    def test_connection(self) -> Dict[str, Any]:
        """Проверяет связь с TRON API и возвращает номер последнего блока."""
        data = self._request_json("POST", "/wallet/getnowblock", {}, max_retries=1)
        header = data.get("block_header", {}).get("raw_data", {})
        block_num = int(header.get("number", 0))
        if block_num <= 0 and not data.get("blockID"):
            raise RuntimeError("Неожиданный ответ TRON API (проверьте URL эндпоинта)")
        return {"network": "TRON", "blocks": block_num, "block_id": data.get("blockID", "")}

    def get_transaction_by_id(self, txid: str) -> Dict[str, Any]:
        """Возвращает полную транзакцию TRON (включая массив signature и raw_data)."""
        return self._request_json("POST", "/wallet/gettransactionbyid", {"value": txid.strip()})

    def get_transactions_by_address(
        self,
        address: str,
        max_transactions: int = 200,
        only_from: bool = True,
        stop_event: Optional[threading.Event] = None,
        on_page: Optional[Callable[[int], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Загружает историю транзакций для TRON-адреса через TronGrid v1 API с пагинацией.
        max_transactions == 0 означает загрузку всех доступных транзакций.
        """
        collected: List[Dict[str, Any]] = []
        fingerprint: Optional[str] = None
        limit = int(max_transactions)

        while limit == 0 or len(collected) < limit:
            if stop_event and stop_event.is_set():
                break
            req_limit = 200 if limit == 0 else min(200, limit - len(collected))
            params: Dict[str, Any] = {
                "limit": max(1, req_limit),
                "only_confirmed": "true",
            }
            if only_from:
                params["only_from"] = "true"
            if fingerprint:
                params["fingerprint"] = fingerprint

            query = urllib.parse.urlencode(params)
            path = f"/v1/accounts/{urllib.parse.quote(address.strip())}/transactions?{query}"
            try:
                resp = self._request_json("GET", path)
            except Exception as exc:
                if collected:
                    self._log(
                        "WARNING",
                        f"[TRON] Остановка пагинации для {address} после {len(collected)} TX: {exc}. "
                        f"Проверяем уже загруженные транзакции...",
                    )
                    break
                raise

            items = resp.get("data", [])
            if not isinstance(items, list) or not items:
                break
            collected.extend(item for item in items if isinstance(item, dict))
            if on_page:
                on_page(len(collected))

            meta = resp.get("meta", {})
            fingerprint = meta.get("fingerprint") if isinstance(meta, dict) else None
            if not fingerprint:
                break

        return collected[:limit] if limit > 0 else collected

    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            total = self.total_requests
            failed = self.failed_requests
            retries = self.retry_count
            rate = ((total - failed) / total * 100.0) if total > 0 else 100.0
            return {
                "total_requests": total,
                "failed_requests": failed,
                "retry_count": retries,
                "success_rate": max(0.0, rate),
            }
