"""Потокобезопасный Bitcoin JSON-RPC 2.0 клиент с Basic Auth, rate-limit и retry."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional


class RPCClient:
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8332",
        username: str = "",
        password: str = "",
        rate_limit: int = 10,
        batch_size: int = 10,
        timeout: int = 30,
        logger: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.endpoint = endpoint.strip()
        self.username = username
        self.password = password
        self.requests_per_second = max(1, int(rate_limit))
        self.batch_size = max(1, int(batch_size))
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
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Bitcoin-ECDSA-CyberScanner/2.0",
        }
        if self.username or self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        if "quicknode" in self.endpoint.lower():
            headers["X-Requested-With"] = "XMLHttpRequest"
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

    def execute_with_retry(self, payload: Any, max_retries: int = 3) -> Any:
        retry = 0
        backoff_sec = 0.1
        body = json.dumps(payload).encode("utf-8")
        headers = self._build_headers()
        last_error: Optional[Exception] = None

        while retry <= max_retries:
            try:
                self.enforce_rate_limit()
                req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                with self._stats_lock:
                    self.total_requests += 1

                if not raw.strip():
                    raise RuntimeError("Пустой ответ от RPC-сервера")

                parsed = json.loads(raw)

                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict) and item.get("error") is not None:
                            raise RuntimeError(f"Ошибка RPC в пакете: {item['error']}")
                elif isinstance(parsed, dict) and parsed.get("error") is not None:
                    raise RuntimeError(f"Ошибка RPC: {parsed['error']}")

                return parsed

            except urllib.error.HTTPError as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                err_body = ""
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass
                last_error = RuntimeError(f"HTTP {exc.code}: {exc.reason} {err_body}".strip())
                if exc.code in (401, 403):
                    raise last_error from exc
            except Exception as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                last_error = exc

            if retry < max_retries:
                self._log("WARNING", f"Повтор RPC-запроса ({retry + 1}/{max_retries}): {last_error}")
                time.sleep(backoff_sec)
                backoff_sec = min(backoff_sec * 2.0, 5.0)
                with self._stats_lock:
                    self.retry_count += 1
            retry += 1

        raise RuntimeError(f"Превышено число попыток RPC ({max_retries}): {last_error}")

    def test_connection(self) -> Dict[str, Any]:
        """Проверяет связь с Bitcoin Core и возвращает информацию о сети и высоте блока."""
        info = self.execute_with_retry(
            {"jsonrpc": "2.0", "method": "getblockchaininfo", "params": [], "id": 1},
            max_retries=1,
        )
        result = info.get("result", {}) if isinstance(info, dict) else {}
        return {
            "chain": result.get("chain", "unknown"),
            "blocks": int(result.get("blocks", 0)),
            "headers": int(result.get("headers", 0)),
            "verificationprogress": float(result.get("verificationprogress", 0.0)),
        }

    def get_block_count(self) -> int:
        resp = self.execute_with_retry(
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1}
        )
        if not isinstance(resp, dict) or resp.get("result") is None:
            raise RuntimeError("Не удалось получить текущую высоту блокчейна (getblockcount)")
        return int(resp["result"])

    def get_block(self, height: int) -> Dict[str, Any]:
        hash_resp = self.execute_with_retry(
            {"jsonrpc": "2.0", "method": "getblockhash", "params": [height], "id": 1}
        )
        block_hash = hash_resp.get("result") if isinstance(hash_resp, dict) else None
        if not block_hash:
            raise RuntimeError(f"Не удалось получить хэш блока {height}")

        block_resp = self.execute_with_retry(
            {"jsonrpc": "2.0", "method": "getblock", "params": [block_hash, 2], "id": 2}
        )
        block_data = block_resp.get("result") if isinstance(block_resp, dict) else None
        if not isinstance(block_data, dict):
            raise RuntimeError(f"Некорректные данные блока {height}")
        return block_data

    def batch_get_blocks(self, heights: List[int]) -> List[Dict[str, Any]]:
        if not heights:
            return []
        hash_batch = [
            {"jsonrpc": "2.0", "method": "getblockhash", "params": [h], "id": idx}
            for idx, h in enumerate(heights)
        ]
        hash_responses = self.execute_with_retry(hash_batch)
        if not isinstance(hash_responses, list):
            return []

        block_batch = []
        for item in hash_responses:
            if isinstance(item, dict) and item.get("result"):
                block_batch.append(
                    {
                        "jsonrpc": "2.0",
                        "method": "getblock",
                        "params": [item["result"], 2],
                        "id": item.get("id", 0),
                    }
                )
        if not block_batch:
            return []

        block_responses = self.execute_with_retry(block_batch)
        if not isinstance(block_responses, list):
            return []
        return [
            item["result"]
            for item in block_responses
            if isinstance(item, dict) and isinstance(item.get("result"), dict)
        ]

    def get_raw_transaction(self, txid: str) -> Dict[str, Any]:
        resp = self.execute_with_retry(
            {"jsonrpc": "2.0", "method": "getrawtransaction", "params": [txid, True], "id": 1}
        )
        res = resp.get("result") if isinstance(resp, dict) else None
        if not isinstance(res, dict):
            raise RuntimeError(f"Не удалось получить транзакцию {txid}")
        return res

    def batch_get_raw_transactions(self, txids: List[str]) -> List[Dict[str, Any]]:
        if not txids:
            return []
        batch = [
            {"jsonrpc": "2.0", "method": "getrawtransaction", "params": [txid, True], "id": idx}
            for idx, txid in enumerate(txids)
        ]
        responses = self.execute_with_retry(batch)
        if not isinstance(responses, list):
            return []
        return [
            item["result"]
            for item in responses
            if isinstance(item, dict) and isinstance(item.get("result"), dict)
        ]

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
