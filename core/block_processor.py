"""Многопоточный обработчик блоков и детектор повторов R-значений ECDSA."""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from core import utils
from core.cache_manager import LRUCache
from core.database_manager import DatabaseManager
from core.key_recovery import KeyRecovery
from core.rpc_client import RPCClient
from core.signature_analyzer import Signature, SignatureAnalyzer


@dataclass
class ProcessingStats:
    blocks_processed: int = 0
    total_blocks: int = 0
    transactions_processed: int = 0
    signatures_processed: int = 0
    r_value_reuses_found: int = 0
    vulnerabilities_flagged: int = 0
    processing_time_ms: int = 0
    errors_count: int = 0


class BlockProcessor:
    def __init__(
        self,
        rpc_client: RPCClient,
        signature_analyzer: SignatureAnalyzer,
        db_manager: DatabaseManager,
        block_cache: LRUCache[int, Dict[str, Any]],
        transaction_cache: LRUCache[str, Dict[str, Any]],
        r_value_cache: LRUCache[str, List[Signature]],
        threads: int = 4,
        batch_size: int = 10,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_progress: Optional[Callable[[ProcessingStats], None]] = None,
        on_detection: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.rpc_client = rpc_client
        self.signature_analyzer = signature_analyzer
        self.db_manager = db_manager
        self.block_cache = block_cache
        self.transaction_cache = transaction_cache
        self.r_value_cache = r_value_cache
        self.num_threads = max(1, int(threads))
        self.batch_size = max(1, int(batch_size))

        self.on_log = on_log
        self.on_progress = on_progress
        self.on_detection = on_detection

        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._r_lock = threading.Lock()
        self._seen_pairs: set[tuple[str, str, str]] = set()
        self._stats = ProcessingStats()
        self._key_recovery = KeyRecovery()
        self._workers: List[threading.Thread] = []
        self._block_queue: queue.Queue[int] = queue.Queue()

    def _log(self, level: str, msg: str) -> None:
        if self.on_log:
            self.on_log(level, msg)

    def get_stats(self) -> ProcessingStats:
        with self._stats_lock:
            return ProcessingStats(
                blocks_processed=self._stats.blocks_processed,
                total_blocks=self._stats.total_blocks,
                transactions_processed=self._stats.transactions_processed,
                signatures_processed=self._stats.signatures_processed,
                r_value_reuses_found=self._stats.r_value_reuses_found,
                vulnerabilities_flagged=self._stats.vulnerabilities_flagged,
                processing_time_ms=self._stats.processing_time_ms,
                errors_count=self._stats.errors_count,
            )

    def stop(self) -> None:
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def start_processing(self, start_height: int, end_height: int) -> ProcessingStats:
        self._stop_event.clear()
        total = max(0, end_height - start_height + 1)
        with self._stats_lock:
            self._stats = ProcessingStats(total_blocks=total)
        with self._r_lock:
            self._seen_pairs.clear()

        self._block_queue = queue.Queue()
        for height in range(start_height, end_height + 1):
            self._block_queue.put(height)

        self._workers = []
        t0 = time.monotonic()

        worker_count = min(self.num_threads, max(1, total))
        for idx in range(worker_count):
            t = threading.Thread(target=self._worker_loop, name=f"ScannerWorker-{idx+1}", daemon=True)
            t.start()
            self._workers.append(t)

        for t in self._workers:
            t.join()

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        with self._stats_lock:
            self._stats.processing_time_ms = elapsed_ms

        self.db_manager.flush_buffer()
        final_stats = self.get_stats()
        self.db_manager.update_statistics(
            final_stats.blocks_processed,
            final_stats.transactions_processed,
            final_stats.signatures_processed,
            final_stats.r_value_reuses_found,
            final_stats.vulnerabilities_flagged,
        )
        if self.on_progress:
            self.on_progress(final_stats)
        return final_stats

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                height = self._block_queue.get_nowait()
            except queue.Empty:
                break

            try:
                self.process_block(height)
            except Exception as exc:
                with self._stats_lock:
                    self._stats.errors_count += 1
                self._log("ERROR", f"Ошибка обработки блока #{height}: {exc}")
            finally:
                self._block_queue.task_done()

    def process_block(self, height: int) -> None:
        if self._stop_event.is_set():
            return

        cached_block = self.block_cache.get(height)
        if cached_block is not None:
            block_data = cached_block
        else:
            block_data = self.rpc_client.get_block(height)
            self.block_cache.put(height, block_data)

        txs = block_data.get("tx")
        if not isinstance(txs, list):
            self._log("WARNING", f"Блок #{height} не содержит массива транзакций")
            return

        for tx in txs:
            if self._stop_event.is_set():
                return
            if isinstance(tx, dict):
                self.process_transaction(tx, height)

        with self._stats_lock:
            self._stats.blocks_processed += 1
            snapshot = ProcessingStats(**self._stats.__dict__)

        if self.on_progress:
            self.on_progress(snapshot)

    def process_transaction(self, tx: Dict[str, Any], block_height: int) -> None:
        txid = str(tx.get("txid", ""))
        if txid and self.transaction_cache.get(txid) is None:
            self.transaction_cache.put(txid, tx)

        signatures = self.signature_analyzer.analyze_transaction(tx, block_height)
        if not signatures:
            return

        self.db_manager.batch_insert_signatures(signatures)
        for sig in signatures:
            self.check_r_value_reuse(sig)

        with self._stats_lock:
            self._stats.transactions_processed += 1
            self._stats.signatures_processed += len(signatures)

    def check_r_value_reuse(self, sig: Signature) -> None:
        with self._r_lock:
            existing_list = self.r_value_cache.get(sig.r)
            candidates: List[Signature] = list(existing_list) if existing_list else []

            if not candidates and not self.db_manager.dry_run:
                db_sigs = self.db_manager.find_signatures_by_r(sig.r)
                if db_sigs:
                    candidates = db_sigs

            for existing_sig in candidates:
                if existing_sig.txid == sig.txid and existing_sig.input_index == sig.input_index:
                    continue

                id_a = f"{existing_sig.txid}#{existing_sig.input_index}"
                id_b = f"{sig.txid}#{sig.input_index}"
                pair_key = (min(id_a, id_b), max(id_a, id_b), sig.r)
                if pair_key in self._seen_pairs:
                    continue
                self._seen_pairs.add(pair_key)

                with self._stats_lock:
                    self._stats.r_value_reuses_found += 1

                same_signer = (existing_sig.pubkey == sig.pubkey) or (
                    bool(sig.address)
                    and existing_sig.address == sig.address
                    and sig.address not in ("UNKNOWN_BTC", "UNKNOWN_TRON")
                )
                if same_signer:
                    marker = self._key_recovery.recover_private_key(existing_sig, sig)
                    if marker:
                        with self._stats_lock:
                            self._stats.vulnerabilities_flagged += 1

                        tx1_label = (
                            f"{existing_sig.txid}#in{existing_sig.input_index}"
                            if existing_sig.txid == sig.txid
                            else existing_sig.txid
                        )
                        tx2_label = (
                            f"{sig.txid}#in{sig.input_index}"
                            if existing_sig.txid == sig.txid
                            else sig.txid
                        )
                        self.db_manager.store_recovered_key(
                            tx1_label, tx2_label, sig.r, marker, sig.address
                        )
                        record = {
                            "network": "BTC",
                            "txid1": tx1_label,
                            "txid2": tx2_label,
                            "block1": existing_sig.block_height,
                            "block2": sig.block_height,
                            "r": sig.r,
                            "address": sig.address,
                            "status_marker": marker,
                            "recovered_at": utils.get_timestamp(),
                        }
                        self._log(
                            "ALERT",
                            f"ОБНАРУЖЕН ПОВТОР R! Адрес: {sig.address} | R: {sig.r[:16]}... | "
                            f"TX1: {tx1_label[:16]}... / TX2: {tx2_label[:16]}... | {marker}",
                        )
                        if self.on_detection:
                            self.on_detection(record)

            if not any(s.txid == sig.txid and s.input_index == sig.input_index for s in candidates):
                candidates.append(sig)
            self.r_value_cache.put(sig.r, candidates)
