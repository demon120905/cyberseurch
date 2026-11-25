"""Многопоточный обработчик загруженных CSV и TXT файлов (TRON и BTC) с детектором повторов R."""

from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from core import utils
from core.block_processor import ProcessingStats
from core.btc_rest_client import BTCRestClient
from core.cache_manager import LRUCache
from core.database_manager import DatabaseManager
from core.file_loader import ImportedAddress, ImportedTransaction, LoadedDataset
from core.key_recovery import KeyRecovery
from core.rpc_client import RPCClient
from core.signature_analyzer import Signature, SignatureAnalyzer
from core.tron_client import TronAPIClient


class FileScanProcessor:
    """
    Сканирует данные из CSV (транзакции / готовые подписи / адреса) и TXT (адреса / TXID).
    Полностью потокобезопасен, поддерживает корректную остановку, живую ленту проверенных подписей и запись в SQLite.
    """

    def __init__(
        self,
        dataset: LoadedDataset,
        signature_analyzer: SignatureAnalyzer,
        db_manager: DatabaseManager,
        r_value_cache: LRUCache[str, List[Signature]],
        network_override: str = "AUTO",
        tron_client: Optional[TronAPIClient] = None,
        btc_rest_client: Optional[BTCRestClient] = None,
        btc_rpc_client: Optional[RPCClient] = None,
        threads: int = 4,
        only_success: bool = True,
        filter_address: str = "",
        max_items: int = 0,
        max_tx_per_address: int = 200,
        only_outgoing_address_tx: bool = True,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_progress: Optional[Callable[[ProcessingStats], None]] = None,
        on_detection: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_signature: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.dataset = dataset
        self.signature_analyzer = signature_analyzer
        self.db_manager = db_manager
        self.r_value_cache = r_value_cache
        self.network_override = network_override.upper()
        self.tron_client = tron_client
        self.btc_rest_client = btc_rest_client
        self.btc_rpc_client = btc_rpc_client
        self.num_threads = max(1, int(threads))

        self.only_success = only_success
        self.filter_address = filter_address.strip()
        self.max_items = max(0, int(max_items))
        self.max_tx_per_address = max(0, int(max_tx_per_address))
        self.only_outgoing_address_tx = only_outgoing_address_tx

        self.on_log = on_log
        self.on_progress = on_progress
        self.on_detection = on_detection
        self.on_signature = on_signature

        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._r_lock = threading.Lock()
        self._seen_pairs: set[tuple[str, str, str]] = set()
        self._seen_txids: set[str] = set()
        self._stats = ProcessingStats()
        self._key_recovery = KeyRecovery()

    def _log(self, level: str, msg: str) -> None:
        if self.on_log:
            self.on_log(level, msg)

    def stop(self) -> None:
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def get_stats(self) -> ProcessingStats:
        with self._stats_lock:
            return ProcessingStats(**self._stats.__dict__)

    def _emit_progress(self) -> None:
        if self.on_progress:
            self.on_progress(self.get_stats())

    def _resolve_tx_network(self, tx: ImportedTransaction) -> str:
        if self.network_override in ("TRON", "BTC"):
            return self.network_override
        if tx.network in ("TRON", "BTC"):
            return tx.network
        if self.dataset.network in ("TRON", "BTC"):
            return self.dataset.network
        return "TRON" if self.tron_client is not None else "BTC"

    def _prepare_transactions(self) -> List[ImportedTransaction]:
        items = list(self.dataset.transactions)
        if self.only_success and self.dataset.dataset_kind == "csv_transactions":
            items = [t for t in items if t.result not in ("FAIL", "FAILED", "REVERT", "ERROR")]
        if self.filter_address:
            flt = self.filter_address.lower()
            items = [
                t
                for t in items
                if t.sender.lower() == flt or t.recipient.lower() == flt
            ]
        if self.max_items > 0:
            items = items[: self.max_items]
        return items

    def start_processing(self) -> ProcessingStats:
        self._stop_event.clear()
        with self._r_lock:
            self._seen_pairs.clear()
            self._seen_txids.clear()

        t0 = time.monotonic()

        # 1) Режим готовых подписей из CSV (офлайн, без сетевых запросов)
        if self.dataset.dataset_kind == "csv_signatures":
            txs = self._prepare_transactions()
            with self._stats_lock:
                self._stats = ProcessingStats(total_blocks=len(txs))
            self._log("INFO", f"Офлайн-проверка готовых ECDSA-подписей из CSV: {len(txs)} строк...")
            for idx, item in enumerate(txs):
                if self._stop_event.is_set():
                    break
                addr = item.sender or "CSV_SIGNER"
                pk = item.pubkey or f"csv:{addr}"
                sig = Signature(
                    txid=item.txid,
                    block_height=item.block,
                    address=addr,
                    pubkey=pk,
                    r=item.r,
                    s=item.s,
                    z=item.z or item.txid,
                    script_type="csv_offline",
                    input_index=idx,
                )
                self._register_signatures([sig], increment_tx=True)
                with self._stats_lock:
                    self._stats.blocks_processed = idx + 1
                if (idx + 1) % 20 == 0 or idx + 1 == len(txs):
                    self._emit_progress()
            return self._finalize(t0)

        # 2) Подготовка очереди задач (адреса + транзакции)
        addresses: List[ImportedAddress] = list(self.dataset.addresses)
        if self.max_items > 0 and self.dataset.dataset_kind in ("txt_addresses", "csv_addresses"):
            addresses = addresses[: self.max_items]

        txs = self._prepare_transactions()
        with self._stats_lock:
            self._stats = ProcessingStats(total_blocks=len(txs))

        if not addresses and not txs:
            self._log("WARNING", "После применения фильтров не осталось объектов для проверки.")
            return self._finalize(t0)

        self._log(
            "INFO",
            f"Подготовлено к сканированию: адресов={len(addresses)}, отдельных TXID={len(txs)} "
            f"(потоков: {self.num_threads}).",
        )

        for addr_item in addresses:
            if self._stop_event.is_set():
                break
            self._process_address_item(addr_item)

        if txs and not self._stop_event.is_set():
            tx_queue: queue.Queue[ImportedTransaction] = queue.Queue()
            for item in txs:
                tx_queue.put(item)

            worker_count = min(self.num_threads, len(txs))
            workers: List[threading.Thread] = []
            for idx in range(worker_count):
                t = threading.Thread(
                    target=self._tx_worker,
                    args=(tx_queue,),
                    name=f"FileScanWorker-{idx + 1}",
                    daemon=True,
                )
                t.start()
                workers.append(t)
            for t in workers:
                t.join()

        return self._finalize(t0)

    def _finalize(self, t0: float) -> ProcessingStats:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        with self._stats_lock:
            self._stats.processing_time_ms = elapsed_ms
            if self._stats.total_blocks == 0 and self._stats.blocks_processed > 0:
                self._stats.total_blocks = self._stats.blocks_processed
        self.db_manager.flush_buffer()
        final_stats = self.get_stats()
        self.db_manager.update_statistics(
            final_stats.blocks_processed,
            final_stats.transactions_processed,
            final_stats.signatures_processed,
            final_stats.r_value_reuses_found,
            final_stats.vulnerabilities_flagged,
        )
        self._emit_progress()
        return final_stats

    def _process_address_item(self, addr_item: ImportedAddress) -> None:
        net = self.network_override if self.network_override in ("TRON", "BTC") else addr_item.network
        lim_text = "все" if self.max_tx_per_address == 0 else str(self.max_tx_per_address)
        self._log("INFO", f"[{net}] Загрузка транзакций для адреса {addr_item.address} (лимит: {lim_text})...")

        def on_page(count: int) -> None:
            self._log("INFO", f"[{net}] {addr_item.address}: загружено {count} транзакций...")

        try:
            if net == "TRON":
                if not self.tron_client:
                    raise RuntimeError("Не настроен клиент TRON API")
                raw_txs = self.tron_client.get_transactions_by_address(
                    addr_item.address,
                    max_transactions=self.max_tx_per_address,
                    only_from=self.only_outgoing_address_tx,
                    stop_event=self._stop_event,
                    on_page=on_page,
                )
            else:
                if not self.btc_rest_client:
                    raise RuntimeError("Для проверки BTC-адресов требуется публичный BTC REST API")
                raw_txs = self.btc_rest_client.get_transactions_by_address(
                    addr_item.address,
                    max_transactions=self.max_tx_per_address,
                    stop_event=self._stop_event,
                    on_page=on_page,
                )
        except Exception as exc:
            with self._stats_lock:
                self._stats.errors_count += 1
            self._log("ERROR", f"Ошибка загрузки транзакций для адреса {addr_item.address}: {exc}")
            return

        if not raw_txs:
            self._log("WARNING", f"[{net}] По адресу {addr_item.address} не найдено транзакций.")
            return

        with self._stats_lock:
            self._stats.total_blocks += len(raw_txs)
        self._emit_progress()

        self._log(
            "INFO",
            f"[{net}] {addr_item.address}: получено {len(raw_txs)} транзакций. "
            f"Начинаем разбор ECDSA-подписей и проверку повторов R (включая повторы внутри одной TX)...",
        )

        checked_txs = 0
        extracted_sigs = 0
        skipped_no_sig = 0
        reuses_before = self.get_stats().r_value_reuses_found

        for idx, raw_tx in enumerate(raw_txs, 1):
            if self._stop_event.is_set():
                break

            if net == "TRON":
                txid = str(raw_tx.get("txID") or "").lower()
                if txid:
                    with self._r_lock:
                        if txid in self._seen_txids:
                            with self._stats_lock:
                                self._stats.blocks_processed += 1
                            continue
                        self._seen_txids.add(txid)

                sigs = self.signature_analyzer.analyze_tron_transaction(
                    raw_tx, fallback_address=addr_item.address
                )
                if not sigs and txid and self.tron_client and not raw_tx.get("signature"):
                    try:
                        full_tx = self.tron_client.get_transaction_by_id(txid)
                        sigs = self.signature_analyzer.analyze_tron_transaction(
                            full_tx, fallback_address=addr_item.address
                        )
                    except Exception:
                        pass
            else:
                txid = str(raw_tx.get("txid") or "").lower()
                if txid:
                    with self._r_lock:
                        if txid in self._seen_txids:
                            with self._stats_lock:
                                self._stats.blocks_processed += 1
                            continue
                        self._seen_txids.add(txid)

                flt = addr_item.address if self.only_outgoing_address_tx else ""
                sigs = self.signature_analyzer.analyze_esplora_btc_tx(raw_tx, filter_address=flt)

            checked_txs += 1
            if sigs:
                extracted_sigs += len(sigs)
            else:
                skipped_no_sig += 1

            self._register_signatures(sigs, increment_tx=True)
            with self._stats_lock:
                self._stats.blocks_processed += 1

            if idx % 5 == 0 or idx == len(raw_txs):
                self._emit_progress()

        reuses_found_here = self.get_stats().r_value_reuses_found - reuses_before
        self._log(
            "SUCCESS",
            f"[{net}] Готово по {addr_item.address}: проверено {checked_txs} TX | "
            f"извлечено подписей ECDSA: {extracted_sigs} | без подписи этого адреса: {skipped_no_sig} | "
            f"повторов R: {reuses_found_here}",
        )
        if net == "BTC" and extracted_sigs == 0 and checked_txs > 0 and self.only_outgoing_address_tx:
            self._log(
                "WARNING",
                f"[BTC] Для {addr_item.address} не найдено исходящих ECDSA-подписей "
                f"(возможно, адрес только получал переводы или использует Taproot bc1p). "
                f"Чтобы проверять и чужие подписи во входящих TX, снимите галочку «Только исходящие TX».",
            )

    def _tx_worker(self, tx_queue: "queue.Queue[ImportedTransaction]") -> None:
        while not self._stop_event.is_set():
            try:
                item = tx_queue.get_nowait()
            except queue.Empty:
                break

            try:
                self._process_single_tx(item)
            except Exception as exc:
                with self._stats_lock:
                    self._stats.errors_count += 1
                self._log("ERROR", f"Ошибка TX {item.txid[:14]}...: {exc}")
            finally:
                with self._stats_lock:
                    self._stats.blocks_processed += 1
                self._emit_progress()
                tx_queue.task_done()

    def _process_single_tx(self, item: ImportedTransaction) -> None:
        with self._r_lock:
            if item.txid in self._seen_txids:
                return
            self._seen_txids.add(item.txid)

        net = self._resolve_tx_network(item)
        if net == "TRON":
            if not self.tron_client:
                raise RuntimeError("Не настроен клиент TRON API")
            raw_tx = self.tron_client.get_transaction_by_id(item.txid)
            sigs = self.signature_analyzer.analyze_tron_transaction(
                raw_tx, block_height=item.block, fallback_address=item.sender
            )
            self._register_signatures(sigs, increment_tx=True)
        else:
            if self.btc_rpc_client:
                raw_tx = self.btc_rpc_client.get_raw_transaction(item.txid)
                sigs = self.signature_analyzer.analyze_transaction(raw_tx, block_height=item.block)
            elif self.btc_rest_client:
                raw_tx = self.btc_rest_client.get_transaction(item.txid)
                sigs = self.signature_analyzer.analyze_esplora_btc_tx(raw_tx)
            else:
                raise RuntimeError("Не настроен клиент BTC (REST API или RPC)")
            self._register_signatures(sigs, increment_tx=True)

    def _register_signatures(self, signatures: List[Signature], increment_tx: bool) -> None:
        if signatures:
            self.db_manager.batch_insert_signatures(signatures)
            for sig in signatures:
                is_reuse = self._check_r_reuse(sig)
                if self.on_signature:
                    net_label = "TRON" if sig.script_type.startswith("tron") else "BTC"
                    self.on_signature(
                        {
                            "network": net_label,
                            "address": sig.address,
                            "txid": f"{sig.txid} [in#{sig.input_index}]" if sig.input_index > 0 else sig.txid,
                            "block": sig.block_height,
                            "script_type": sig.script_type,
                            "r": sig.r,
                            "s": sig.s,
                            "status": "ПОВТОР R!" if is_reuse else "OK (уникальный R)",
                        }
                    )
        with self._stats_lock:
            if increment_tx:
                self._stats.transactions_processed += 1
            self._stats.signatures_processed += len(signatures)

    def _check_r_reuse(self, sig: Signature) -> bool:
        found_reuse = False
        with self._r_lock:
            existing_list = self.r_value_cache.get(sig.r)
            candidates: List[Signature] = list(existing_list) if existing_list else []

            if not candidates and not self.db_manager.dry_run:
                db_sigs = self.db_manager.find_signatures_by_r(sig.r)
                if db_sigs:
                    candidates = db_sigs

            for existing_sig in candidates:
                # Пропускаем ТОЛЬКО ту же самую подпись (тот же TXID и тот же input_index),
                # а разные входы одной TX (txid1 == txid2, in1 != in2) ОБЯЗАТЕЛЬНО проверяем!
                if existing_sig.txid == sig.txid and existing_sig.input_index == sig.input_index:
                    continue

                id_a = f"{existing_sig.txid}#{existing_sig.input_index}"
                id_b = f"{sig.txid}#{sig.input_index}"
                pair_key = (min(id_a, id_b), max(id_a, id_b), sig.r)
                if pair_key in self._seen_pairs:
                    continue
                self._seen_pairs.add(pair_key)

                found_reuse = True
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
                        net_label = "TRON" if sig.script_type.startswith("tron") else "BTC"
                        record = {
                            "network": net_label,
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
                            f"[{net_label}] ОБНАРУЖЕН ПОВТОР R! Адрес: {sig.address} | R: {sig.r[:16]}... | "
                            f"TX1: {tx1_label[:16]}... / TX2: {tx2_label[:16]}... | {marker}",
                        )
                        if self.on_detection:
                            self.on_detection(record)

            if not any(s.txid == sig.txid and s.input_index == sig.input_index for s in candidates):
                candidates.append(sig)
            self.r_value_cache.put(sig.r, candidates)
        return found_reuse
