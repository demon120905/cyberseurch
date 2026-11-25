"""Потокобезопасный менеджер базы данных SQLite3 (WAL-режим, пакетная вставка, экспорт)."""

from __future__ import annotations

import csv
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from core.signature_analyzer import Signature


class DatabaseManager:
    def __init__(self, db_path: str = "btc_scanner.db", dry_run: bool = False) -> None:
        self.db_path = db_path
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self._signature_buffer: List[Signature] = []
        self.buffer_size = 500
        self._conn: Optional[sqlite3.Connection] = None

        if not self.dry_run:
            self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            self.enable_wal_mode()
            self.initialize_schema()
            self.create_indexes()
            self.optimize_performance()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._flush_buffer_unlocked()
                except Exception:
                    pass
                self._conn.close()
                self._conn = None

    def enable_wal_mode(self) -> None:
        if self._conn is None:
            return
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA wal_autocheckpoint=1000")

    def optimize_performance(self) -> None:
        if self._conn is None:
            return
        pragmas = [
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=10000",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA optimize",
        ]
        for pragma in pragmas:
            try:
                self._conn.execute(pragma)
            except sqlite3.Error:
                pass

    def initialize_schema(self) -> None:
        if self._conn is None:
            return
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid TEXT NOT NULL,
                    block_height INTEGER NOT NULL,
                    input_index INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    pubkey TEXT NOT NULL,
                    r TEXT NOT NULL,
                    s TEXT NOT NULL,
                    z TEXT NOT NULL,
                    script_type TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(txid, input_index)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS recovered_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid1 TEXT NOT NULL,
                    txid2 TEXT NOT NULL,
                    r TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    address TEXT NOT NULL,
                    recovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(txid1, txid2)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY,
                    blocks_scanned INTEGER DEFAULT 0,
                    transactions_processed INTEGER DEFAULT 0,
                    signatures_processed INTEGER DEFAULT 0,
                    r_value_reuses INTEGER DEFAULT 0,
                    keys_recovered INTEGER DEFAULT 0,
                    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._conn.execute("INSERT OR IGNORE INTO statistics (id) VALUES (1)")

    def create_indexes(self) -> None:
        if self._conn is None:
            return
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_r ON signatures(r)",
            "CREATE INDEX IF NOT EXISTS idx_pubkey ON signatures(pubkey)",
            "CREATE INDEX IF NOT EXISTS idx_address ON signatures(address)",
            "CREATE INDEX IF NOT EXISTS idx_txid ON signatures(txid)",
            "CREATE INDEX IF NOT EXISTS idx_r_pubkey ON signatures(r, pubkey)",
            "CREATE INDEX IF NOT EXISTS idx_address_script ON signatures(address, script_type)",
            "CREATE INDEX IF NOT EXISTS idx_block_height ON signatures(block_height)",
            "CREATE INDEX IF NOT EXISTS idx_created_at ON signatures(created_at)",
        ]
        with self._conn:
            for sql in indexes:
                self._conn.execute(sql)

    def _flush_buffer_unlocked(self) -> None:
        if self._conn is None or not self._signature_buffer:
            return
        rows = [
            (
                s.txid,
                s.block_height,
                s.input_index,
                s.address,
                s.pubkey,
                s.r,
                s.s,
                s.z,
                s.script_type,
            )
            for s in self._signature_buffer
        ]
        with self._conn:
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO signatures
                (txid, block_height, input_index, address, pubkey, r, s, z, script_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self._signature_buffer.clear()

    def batch_insert_signatures(self, sigs: List[Signature]) -> None:
        if self.dry_run or not sigs:
            return
        with self._lock:
            self._signature_buffer.extend(sigs)
            if len(self._signature_buffer) >= self.buffer_size:
                self._flush_buffer_unlocked()

    def flush_buffer(self) -> None:
        if self.dry_run:
            return
        with self._lock:
            self._flush_buffer_unlocked()

    def find_signatures_by_r(self, r: str) -> List[Signature]:
        if self.dry_run or self._conn is None:
            return []
        with self._lock:
            self._flush_buffer_unlocked()
            cur = self._conn.execute(
                """
                SELECT txid, block_height, input_index, address, pubkey, r, s, z, script_type
                FROM signatures
                WHERE r = ?
                """,
                (r,),
            )
            rows = cur.fetchall()
        return [
            Signature(
                txid=row["txid"],
                block_height=row["block_height"],
                input_index=row["input_index"],
                address=row["address"],
                pubkey=row["pubkey"],
                r=row["r"],
                s=row["s"],
                z=row["z"],
                script_type=row["script_type"],
            )
            for row in rows
        ]

    def get_recent_r_values(self, limit: int = 100000) -> List[str]:
        if self.dry_run or self._conn is None:
            return []
        with self._lock:
            cur = self._conn.execute(
                "SELECT DISTINCT r FROM signatures ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [row[0] for row in cur.fetchall() if row[0]]

    def store_recovered_key(
        self, txid1: str, txid2: str, r: str, status_marker: str, address: str = ""
    ) -> None:
        if self.dry_run or self._conn is None:
            return
        with self._lock:
            addr = address
            if not addr:
                cur = self._conn.execute(
                    "SELECT address FROM signatures WHERE txid = ? LIMIT 1", (txid1,)
                )
                row = cur.fetchone()
                if row:
                    addr = row["address"]
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO recovered_keys
                    (txid1, txid2, r, private_key, address)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (txid1, txid2, r, status_marker, addr),
                )

    def update_statistics(
        self,
        blocks_scanned: int,
        txs_processed: int,
        sigs_processed: int,
        r_reuses: int,
        keys_recovered: int,
    ) -> None:
        if self.dry_run or self._conn is None:
            return
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE statistics SET
                        blocks_scanned = ?,
                        transactions_processed = ?,
                        signatures_processed = ?,
                        r_value_reuses = ?,
                        keys_recovered = ?,
                        last_update = CURRENT_TIMESTAMP
                    WHERE id = 1
                    """,
                    (blocks_scanned, txs_processed, sigs_processed, r_reuses, keys_recovered),
                )

    def get_all_detections(self) -> List[Dict[str, Any]]:
        if self.dry_run or self._conn is None:
            return []
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT txid1, txid2, r, private_key AS status_marker, address, recovered_at
                FROM recovered_keys
                ORDER BY id DESC
                """
            )
            return [dict(row) for row in cur.fetchall()]

    def export_detections_csv(self, output_path: str, records: Optional[List[Dict[str, Any]]] = None) -> int:
        data = records if records is not None else self.get_all_detections()
        fieldnames = ["txid1", "txid2", "r", "address", "status_marker", "recovered_at"]
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow({k: item.get(k, "") for k in fieldnames})
        return len(data)

    def export_detections_json(self, output_path: str, records: Optional[List[Dict[str, Any]]] = None) -> int:
        data = records if records is not None else self.get_all_detections()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return len(data)
