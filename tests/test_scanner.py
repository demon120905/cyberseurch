"""Автоматические модульные и интеграционные тесты ECDSA Сканера (BTC + TRON, CSV/TXT и RPC)."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from core import utils
from core.block_processor import BlockProcessor
from core.btc_rest_client import BTCRestClient
from core.cache_manager import LRUCache
from core.database_manager import DatabaseManager
from core.file_loader import load_input_file
from core.file_processor import FileScanProcessor
from core.rpc_client import RPCClient
from core.signature_analyzer import SignatureAnalyzer
from core.tron_client import TronAPIClient


def _make_der_sig(r_hex: str, s_hex: str, sighash: int = 0x01) -> bytes:
    rb = bytes.fromhex(r_hex)
    sb = bytes.fromhex(s_hex)
    if rb[0] >= 0x80:
        rb = b"\x00" + rb
    if sb[0] >= 0x80:
        sb = b"\x00" + sb
    inner = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(inner)]) + inner + bytes([sighash])


class TestCryptoAndUtils(unittest.TestCase):
    def test_genesis_pubkey_to_address(self) -> None:
        genesis_pk = bytes.fromhex(
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
            "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        self.assertEqual(utils.pubkey_to_address(genesis_pk), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_tron_address_validation_and_roundtrip(self) -> None:
        addr = "TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC"
        self.assertTrue(utils.is_valid_tron_address(addr))
        self.assertEqual(utils.detect_address_network(addr), "TRON")
        hex_addr = utils.tron_base58_to_hex(addr)
        self.assertTrue(hex_addr.startswith("41"))
        self.assertEqual(len(hex_addr), 42)
        self.assertEqual(utils.tron_hex_to_base58(hex_addr), addr)
        self.assertFalse(utils.is_valid_tron_address("TInvalidAddress123456789012345678"))

    def test_btc_address_detection(self) -> None:
        self.assertEqual(utils.detect_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "BTC")
        self.assertEqual(
            utils.detect_address_network("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "BTC"
        )

    def test_base58_roundtrip(self) -> None:
        sample = b"\x00\x00\x12\x34\xab\xcd\xef"
        encoded = utils.base58_encode(sample)
        self.assertTrue(encoded.startswith("11"))
        self.assertEqual(utils.base58_decode(encoded), sample)

    def test_sighash_serialization(self) -> None:
        tx = {
            "version": 1,
            "locktime": 0,
            "vin": [{"txid": "ab" * 32, "vout": 0, "sequence": 0xFFFFFFFF}],
            "vout": [{"value": 1.0, "scriptPubKey": {"hex": "76a914" + "11" * 20 + "88ac"}}],
        }
        h = utils.compute_transaction_hash(tx, 0, "76a914" + "22" * 20 + "88ac")
        self.assertEqual(len(h), 64)
        self.assertTrue(utils.is_hex_string(h))


class TestCacheAndSignatureAnalyzer(unittest.TestCase):
    def test_lru_cache(self) -> None:
        cache: LRUCache[str, int] = LRUCache(capacity=2)
        cache.put("a", 1)
        cache.put("b", 2)
        self.assertEqual(cache.get("a"), 1)
        cache.put("c", 3)
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("c"), 3)
        self.assertGreater(cache.get_hit_rate(), 0.5)

    def test_der_extraction_low_r_and_segwit(self) -> None:
        analyzer = SignatureAnalyzer()
        # Короткий 31-байтовый R (69-байтовая DER-подпись с low-R)
        r_short = "7f" + "aa" * 30
        s_low = "7e" + "bb" * 30
        der = _make_der_sig(r_short, s_low)
        self.assertEqual(len(der), 69)  # 0x45 — раньше пропускалось!
        r_out, s_out = analyzer.extract_signature_components(der)
        self.assertEqual(r_out, r_short.zfill(64))
        self.assertEqual(s_out, s_low.zfill(64))

        pk_compressed = bytes.fromhex("02" + "33" * 32)
        script_sig = bytes([len(der)]) + der + bytes([len(pk_compressed)]) + pk_compressed
        tx_p2pkh = {
            "txid": "c" * 64,
            "version": 2,
            "locktime": 0,
            "vin": [{"txid": "d" * 64, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": script_sig.hex()}}],
            "vout": [{"value": 0.1, "scriptPubKey": {"hex": "76a914" + "44" * 20 + "88ac"}}],
        }
        sigs = analyzer.analyze_transaction(tx_p2pkh, 800000)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0].r, r_short.zfill(64))

        # Проверка SegWit witness
        tx_sw = {
            "txid": "e" * 64,
            "version": 2,
            "locktime": 0,
            "vin": [{"txid": "d" * 64, "vout": 0, "sequence": 0xFFFFFFFF, "txinwitness": [der.hex(), pk_compressed.hex()]}],
            "vout": [{"value": 0.1, "scriptPubKey": {"hex": "0014" + "44" * 20}}],
        }
        sigs_sw = analyzer.analyze_transaction(tx_sw, 800001)
        self.assertEqual(len(sigs_sw), 1)
        self.assertEqual(sigs_sw[0].script_type, "segwit")

    def test_tron_signature_extraction(self) -> None:
        analyzer = SignatureAnalyzer()
        addr = "TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC"
        owner_hex = utils.tron_base58_to_hex(addr)
        r_val = "aa" * 32
        s_val = "bb" * 32
        tx = {
            "txID": "e" * 64,
            "blockNumber": 88174146,
            "signature": [r_val + s_val + "1b"],
            "raw_data": {
                "contract": [{"type": "TransferContract", "parameter": {"value": {"owner_address": owner_hex}}}]
            },
        }
        sigs = analyzer.analyze_tron_transaction(tx)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0].address, addr)
        self.assertEqual(sigs[0].r, r_val)
        self.assertEqual(sigs[0].s, s_val)
        self.assertEqual(sigs[0].z, "e" * 64)


class TestFileLoaderAndFileProcessor(unittest.TestCase):
    def test_csv_tronscan_and_txt_addresses_loading(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "Transactions_test.csv")
            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                f.write(
                    "Txn Hash,Block,Time (UTC),Transaction Type,Method ID,Method Name,From,To,Token,Token Symbol,Amount,Result,Status\n"
                    f"{'a' * 64},88174146,2026-11-20 17:42:15,TransferContract,'-,'-,TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC,TX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed,0,TRX,10.5,SUCCESS,CONFIRMED\n"
                    f"{'a' * 64},88174146,2026-11-20 17:42:15,TransferContract,'-,'-,TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC,TX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed,0,TRX,10.5,SUCCESS,CONFIRMED\n"
                    f"{'b' * 64},88174147,2026-11-20 17:43:00,TriggerSmartContract,'-,'-,TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC,TX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed,0,TRX,0,FAIL,CONFIRMED\n"
                )
            ds_csv = load_input_file(csv_path)
            self.assertEqual(ds_csv.dataset_kind, "csv_transactions")
            self.assertEqual(ds_csv.network, "TRON")
            self.assertEqual(len(ds_csv.transactions), 2)
            self.assertEqual(ds_csv.duplicates_removed, 1)
            self.assertEqual(ds_csv.success_count, 1)
            self.assertEqual(ds_csv.fail_count, 1)

            txt_path = os.path.join(tmpdir, "Текстовый документ.txt")
            with open(txt_path, "w", encoding="utf-8-sig") as f:
                f.write("# Комментарий\nTY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC\nTX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed\n")
            ds_txt = load_input_file(txt_path)
            self.assertEqual(ds_txt.dataset_kind, "txt_addresses")
            self.assertEqual(ds_txt.network, "TRON")
            self.assertEqual(len(ds_txt.addresses), 2)

    def test_offline_csv_signatures_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "sigs.csv")
            r_dup = "77" * 32
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                f.write(
                    "txid,from,r,s,z\n"
                    f"{'1' * 64},TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC,{r_dup},{'22' * 32},{'aa' * 32}\n"
                    f"{'2' * 64},TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC,{r_dup},{'33' * 32},{'bb' * 32}\n"
                )
            ds = load_input_file(csv_path)
            self.assertEqual(ds.dataset_kind, "csv_signatures")
            db = DatabaseManager(dry_run=True)
            detections = []
            checked_sigs = []
            proc = FileScanProcessor(
                dataset=ds,
                signature_analyzer=SignatureAnalyzer(),
                db_manager=db,
                r_value_cache=LRUCache(100),
                on_detection=detections.append,
                on_signature=checked_sigs.append,
            )
            stats = proc.start_processing()
            self.assertEqual(stats.signatures_processed, 2)
            self.assertEqual(stats.r_value_reuses_found, 1)
            self.assertEqual(stats.vulnerabilities_flagged, 1)
            self.assertEqual(len(detections), 1)
            self.assertEqual(len(checked_sigs), 2)
            db.close()

    def test_mock_btc_esplora_txt_address_pipeline(self) -> None:
        pk_hex = (
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
            "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        addr = utils.pubkey_to_address(bytes.fromhex(pk_hex))
        r_shared = "71" + "aa" * 30  # 31-байтовый low-R
        der1 = _make_der_sig(r_shared, "22" * 32)
        der2 = _make_der_sig(r_shared, "33" * 32)
        pk_b = bytes.fromhex(pk_hex)
        sc1 = (bytes([len(der1)]) + der1 + bytes([len(pk_b)]) + pk_b).hex()
        sc2 = (bytes([len(der2)]) + der2 + bytes([len(pk_b)]) + pk_b).hex()

        esplora_txs = [
            {
                "txid": "1" * 64,
                "version": 1,
                "locktime": 0,
                "status": {"confirmed": True, "block_height": 810001},
                "vin": [
                    {
                        "txid": "a" * 64,
                        "vout": 0,
                        "scriptsig": sc1,
                        "sequence": 0xFFFFFFFF,
                        "prevout": {"scriptpubkey": "76a914" + "00" * 20 + "88ac", "scriptpubkey_address": addr},
                    }
                ],
                "vout": [{"value": 100000, "scriptpubkey": "76a914" + "11" * 20 + "88ac"}],
            },
            {
                "txid": "2" * 64,
                "version": 1,
                "locktime": 1,
                "status": {"confirmed": True, "block_height": 810002},
                "vin": [
                    {
                        "txid": "b" * 64,
                        "vout": 1,
                        "scriptsig": sc2,
                        "sequence": 0xFFFFFFFF,
                        "prevout": {"scriptpubkey": "76a914" + "00" * 20 + "88ac", "scriptpubkey_address": addr},
                    }
                ],
                "vout": [{"value": 50000, "scriptpubkey": "76a914" + "22" * 20 + "88ac"}],
            },
        ]

        class MockEsploraHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path == "/blocks/tip/height":
                    raw = b"870000"
                    ct = "text/plain"
                elif self.path == f"/address/{addr}/txs":
                    raw = json.dumps(esplora_txs).encode("utf-8")
                    ct = "application/json"
                else:
                    raw = b"[]"
                    ct = "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = HTTPServer(("127.0.0.1", 0), MockEsploraHandler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                txt_path = os.path.join(tmpdir, "btc_wallet.txt")
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(addr + "\n")

                ds = load_input_file(txt_path)
                self.assertEqual(ds.network, "BTC")
                client = BTCRestClient(endpoint=f"http://127.0.0.1:{port}", rate_limit=100)
                self.assertEqual(client.test_connection()["blocks"], 870000)

                db = DatabaseManager(os.path.join(tmpdir, "btc.db"), dry_run=False)
                detections = []
                checked_sigs = []
                proc = FileScanProcessor(
                    dataset=ds,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db,
                    r_value_cache=LRUCache(100),
                    btc_rest_client=client,
                    only_outgoing_address_tx=True,
                    on_detection=detections.append,
                    on_signature=checked_sigs.append,
                )
                stats = proc.start_processing()
                self.assertEqual(stats.total_blocks, 2)
                self.assertEqual(stats.blocks_processed, 2)
                self.assertEqual(stats.transactions_processed, 2)
                self.assertEqual(stats.signatures_processed, 2)
                self.assertEqual(stats.vulnerabilities_flagged, 1)
                self.assertEqual(len(detections), 1)
                self.assertEqual(len(checked_sigs), 2)
                db.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_mock_trongrid_csv_and_txt_pipeline(self) -> None:
        addr = "TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC"
        owner_hex = utils.tron_base58_to_hex(addr)
        r_shared = "99" * 32
        tx1 = {
            "txID": "1" * 64,
            "blockNumber": 88000001,
            "signature": [r_shared + ("11" * 32) + "1b"],
            "raw_data": {"contract": [{"type": "TransferContract", "parameter": {"value": {"owner_address": owner_hex}}}]},
        }
        tx2 = {
            "txID": "2" * 64,
            "blockNumber": 88000002,
            "signature": [r_shared + ("22" * 32) + "1c"],
            "raw_data": {"contract": [{"type": "TransferContract", "parameter": {"value": {"owner_address": owner_hex}}}]},
        }
        tx_by_id = {tx1["txID"]: tx1, tx2["txID"]: tx2}

        class MockTronHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body_in = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if self.path == "/wallet/getnowblock":
                    resp = {"blockID": "00" * 32, "block_header": {"raw_data": {"number": 88174200}}}
                elif self.path == "/wallet/gettransactionbyid":
                    resp = tx_by_id.get(body_in.get("value", ""), {})
                else:
                    resp = {}
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if f"/v1/accounts/{addr}/transactions" in self.path:
                    resp = {"data": [tx1, tx2], "meta": {}}
                else:
                    resp = {"data": [], "meta": {}}
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = HTTPServer(("127.0.0.1", 0), MockTronHandler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tron_client = TronAPIClient(endpoint=f"http://127.0.0.1:{port}", rate_limit=100)
                info = tron_client.test_connection()
                self.assertEqual(info["blocks"], 88174200)

                csv_path = os.path.join(tmpdir, "tron_txs.csv")
                with open(csv_path, "w", encoding="utf-8-sig") as f:
                    f.write("Txn Hash,Block,From,To,Result\n")
                    f.write(f"{tx1['txID']},88000001,{addr},TX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed,SUCCESS\n")
                    f.write(f"{tx2['txID']},88000002,{addr},TX3zdBiDuRHUwaVj2CmyB6btZVssLZwNed,SUCCESS\n")
                ds_csv = load_input_file(csv_path)
                db1 = DatabaseManager(os.path.join(tmpdir, "csv.db"), dry_run=False)
                det1 = []
                p1 = FileScanProcessor(
                    dataset=ds_csv,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db1,
                    r_value_cache=LRUCache(100),
                    tron_client=tron_client,
                    threads=2,
                    on_detection=det1.append,
                )
                st1 = p1.start_processing()
                self.assertEqual(st1.signatures_processed, 2)
                self.assertEqual(st1.vulnerabilities_flagged, 1)
                self.assertEqual(len(det1), 1)
                self.assertEqual(det1[0]["network"], "TRON")
                db1.close()

                txt_path = os.path.join(tmpdir, "wallets.txt")
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(f"{addr}\n")
                ds_txt = load_input_file(txt_path)
                db2 = DatabaseManager(os.path.join(tmpdir, "txt.db"), dry_run=False)
                det2 = []
                p2 = FileScanProcessor(
                    dataset=ds_txt,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db2,
                    r_value_cache=LRUCache(100),
                    tron_client=tron_client,
                    on_detection=det2.append,
                )
                st2 = p2.start_processing()
                self.assertEqual(st2.signatures_processed, 2)
                self.assertEqual(st2.vulnerabilities_flagged, 1)
                self.assertEqual(len(det2), 1)
                db2.close()
        finally:
            server.shutdown()
            server.server_close()


class TestEndToEndMockRPC(unittest.TestCase):
    def test_full_pipeline_with_mock_rpc_and_sqlite(self) -> None:
        pk_hex = (
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
            "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        pk_bytes = bytes.fromhex(pk_hex)
        r_shared = "12" * 32
        der1 = _make_der_sig(r_shared, "34" * 32)
        der2 = _make_der_sig(r_shared, "56" * 32)
        script1 = bytes([len(der1)]) + der1 + bytes([len(pk_bytes)]) + pk_bytes
        script2 = bytes([len(der2)]) + der2 + bytes([len(pk_bytes)]) + pk_bytes

        blocks = {
            "hash_100": {
                "height": 100,
                "tx": [
                    {
                        "txid": "a" * 64,
                        "version": 1,
                        "locktime": 0,
                        "vin": [{"txid": "1" * 64, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": script1.hex()}}],
                        "vout": [{"value": 0.5, "scriptPubKey": {"hex": "76a914" + "00" * 20 + "88ac"}}],
                    }
                ],
            },
            "hash_101": {
                "height": 101,
                "tx": [
                    {
                        "txid": "b" * 64,
                        "version": 1,
                        "locktime": 1,
                        "vin": [{"txid": "2" * 64, "vout": 1, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": script2.hex()}}],
                        "vout": [{"value": 0.25, "scriptPubKey": {"hex": "76a914" + "ff" * 20 + "88ac"}}],
                    }
                ],
            },
        }
        expected_auth = "Basic " + base64.b64encode(b"testuser:testpass").decode("ascii")

        class MockRPCHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                if self.headers.get("Authorization") != expected_auth:
                    self.send_response(401)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(length).decode("utf-8"))
                method = req["method"]
                params = req.get("params", [])
                if method == "getblockcount":
                    res = 101
                elif method == "getblockchaininfo":
                    res = {"chain": "main", "blocks": 101, "headers": 101, "verificationprogress": 1.0}
                elif method == "getblockhash":
                    res = f"hash_{params[0]}"
                elif method == "getblock":
                    res = blocks[params[0]]
                else:
                    res = None
                body = json.dumps({"result": res, "error": None, "id": req.get("id", 1)}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), MockRPCHandler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                db_path = os.path.join(tmpdir, "test_scan.db")
                csv_path = os.path.join(tmpdir, "out.csv")
                json_path = os.path.join(tmpdir, "out.json")

                rpc = RPCClient(
                    endpoint=f"http://127.0.0.1:{port}",
                    username="testuser",
                    password="testpass",
                    rate_limit=100,
                )
                info = rpc.test_connection()
                self.assertEqual(info["blocks"], 101)
                self.assertEqual(rpc.get_block_count(), 101)

                db = DatabaseManager(db_path, dry_run=False)
                detections = []
                proc = BlockProcessor(
                    rpc_client=rpc,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db,
                    block_cache=LRUCache(100),
                    transaction_cache=LRUCache(100),
                    r_value_cache=LRUCache(100),
                    threads=2,
                    on_detection=detections.append,
                )
                stats = proc.start_processing(100, 101)
                self.assertEqual(stats.blocks_processed, 2)
                self.assertEqual(stats.signatures_processed, 2)
                self.assertEqual(stats.r_value_reuses_found, 1)
                self.assertEqual(stats.vulnerabilities_flagged, 1)
                self.assertEqual(len(detections), 1)
                self.assertTrue(detections[0]["status_marker"].startswith("VULNERABILITY_DETECTED_"))

                saved = db.get_all_detections()
                self.assertEqual(len(saved), 1)
                self.assertEqual(db.export_detections_csv(csv_path), 1)
                self.assertEqual(db.export_detections_json(json_path), 1)
                self.assertTrue(os.path.exists(csv_path))
                self.assertTrue(os.path.exists(json_path))
                db.close()

                dry_db_path = os.path.join(tmpdir, "should_not_exist.db")
                dry_db = DatabaseManager(dry_db_path, dry_run=True)
                dry_db.close()
                self.assertFalse(os.path.exists(dry_db_path))
        finally:
            server.shutdown()
            server.server_close()



    def test_same_tx_multi_input_r_reuse_detected(self) -> None:
        pk_hex = (
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
            "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        pk_b = bytes.fromhex(pk_hex)
        addr = utils.pubkey_to_address(pk_b)
        r_shared = "55" * 32
        der0 = _make_der_sig(r_shared, "11" * 32)
        der1 = _make_der_sig(r_shared, "22" * 32)
        sc0 = (bytes([len(der0)]) + der0 + bytes([len(pk_b)]) + pk_b).hex()
        sc1 = (bytes([len(der1)]) + der1 + bytes([len(pk_b)]) + pk_b).hex()

        tx_multi = {
            "txid": "f" * 64,
            "version": 1,
            "locktime": 0,
            "status": {"confirmed": True, "block_height": 300000},
            "vin": [
                {
                    "txid": "1" * 64, "vout": 0, "scriptsig": sc0, "sequence": 0xFFFFFFFF,
                    "prevout": {"scriptpubkey": "76a914" + "00" * 20 + "88ac", "scriptpubkey_address": addr},
                },
                {
                    "txid": "2" * 64, "vout": 1, "scriptsig": sc1, "sequence": 0xFFFFFFFF,
                    "prevout": {"scriptpubkey": "76a914" + "00" * 20 + "88ac", "scriptpubkey_address": addr},
                },
            ],
            "vout": [{"value": 100000, "scriptpubkey": "76a914" + "11" * 20 + "88ac"}],
        }
        analyzer = SignatureAnalyzer()
        sigs = analyzer.analyze_esplora_btc_tx(tx_multi, filter_address=addr)
        self.assertEqual(len(sigs), 2)
        self.assertEqual(sigs[0].txid, sigs[1].txid)
        self.assertNotEqual(sigs[0].input_index, sigs[1].input_index)

        from core.key_recovery import KeyRecovery
        kr = KeyRecovery()
        marker = kr.recover_private_key(sigs[0], sigs[1])
        self.assertIsNotNone(marker)
        self.assertIn("SAME_TX", marker)


if __name__ == "__main__":
    unittest.main()
