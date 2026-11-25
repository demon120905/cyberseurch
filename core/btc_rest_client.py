"""Потокобезопасный клиент публичного Bitcoin REST API (Blockstream / Mempool.space Esplora)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional


class BTCRestClient:
    """Клиент для получения транзакций Bitcoin по TXID и адресу без локальной ноды."""

    DEFAULT_ENDPOINT = "https://blockstream.info/api"

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        rate_limit: int = 5,
        timeout: int = 20,
        logger: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.endpoint = (endpoint.strip() or self.DEFAULT_ENDPOINT).rstrip("/")
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

    def _get(self, path: str, expect_json: bool = True, max_retries: int = 3) -> Any:
        url = f"{self.endpoint}{path}"
        headers = {
            "Accept": "application/json" if expect_json else "text/plain",
            "User-Agent": "ECDSA-CyberScanner/3.1",
        }
        retry = 0
        backoff = 0.5
        last_error: Optional[Exception] = None

        while retry <= max_retries:
            try:
                self.enforce_rate_limit()
                req = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                with self._stats_lock:
                    self.total_requests += 1
                if not expect_json:
                    return raw.strip()
                return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                last_error = RuntimeError(f"HTTP {exc.code}: {exc.reason}")
                if exc.code == 429:
                    backoff = max(backoff, 2.0)
                elif exc.code in (400, 404):
                    raise last_error from exc
            except Exception as exc:
                with self._stats_lock:
                    self.failed_requests += 1
                last_error = exc

            if retry < max_retries:
                self._log("WARNING", f"Повтор BTC REST API ({retry + 1}/{max_retries}): {last_error}")
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 6.0)
                with self._stats_lock:
                    self.retry_count += 1
            retry += 1

        raise RuntimeError(f"BTC REST API недоступен после {max_retries} попыток: {last_error}")

    def test_connection(self) -> Dict[str, Any]:
        tip = self._get("/blocks/tip/height", expect_json=False, max_retries=1)
        return {"network": "BTC", "blocks": int(str(tip).strip())}

    def get_transaction(self, txid: str) -> Dict[str, Any]:
        data = self._get(f"/tx/{urllib.parse.quote(txid.strip())}", expect_json=True)
        return data if isinstance(data, dict) else {}

    def get_transactions_by_address(
        self,
        address: str,
        max_transactions: int = 200,
        stop_event: Optional[threading.Event] = None,
        on_page: Optional[Callable[[int], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Загружает историю транзакций BTC-адреса постранично (по 25 TX на страницу).
        max_transactions == 0 означает загрузку всех доступных транзакций.
        При ошибке на последующих страницах возвращает уже загруженные транзакции.
        """
        collected: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()
        last_confirmed_txid: Optional[str] = None
        addr_q = urllib.parse.quote(address.strip())
        limit = int(max_transactions)

        while limit == 0 or len(collected) < limit:
            if stop_event and stop_event.is_set():
                break
            path = (
                f"/address/{addr_q}/txs"
                if not last_confirmed_txid
                else f"/address/{addr_q}/txs/chain/{last_confirmed_txid}"
            )
            try:
                batch = self._get(path, expect_json=True)
            except Exception as exc:
                if collected:
                    self._log(
                        "WARNING",
                        f"[BTC] Остановка пагинации для {address} после {len(collected)} TX: {exc}. "
                        f"Проверяем уже загруженные транзакции...",
                    )
                    break
                raise

            if not isinstance(batch, list) or not batch:
                break

            added_in_batch = 0
            confirmed_in_batch: List[str] = []
            for tx in batch:
                if not isinstance(tx, dict):
                    continue
                tid = str(tx.get("txid", "")).strip().lower()
                if tid and tid not in seen_ids:
                    seen_ids.add(tid)
                    collected.append(tx)
                    added_in_batch += 1
                st = tx.get("status", {})
                if isinstance(st, dict) and st.get("confirmed") and tid:
                    confirmed_in_batch.append(tid)

            if on_page:
                on_page(len(collected))

            if added_in_batch == 0 or len(confirmed_in_batch) < 25:
                break
            last_confirmed_txid = confirmed_in_batch[-1]

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
