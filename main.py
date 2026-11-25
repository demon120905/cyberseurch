"""Точка входа: запуск графического киберпанк-интерфейса Windows или CLI-режима (CSV/TXT и BTC RPC)."""

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import Any, Dict, List

from core import utils
from core.block_processor import BlockProcessor, ProcessingStats
from core.btc_rest_client import BTCRestClient
from core.cache_manager import LRUCache
from core.database_manager import DatabaseManager
from core.file_loader import load_input_file
from core.file_processor import FileScanProcessor
from core.rpc_client import RPCClient
from core.signature_analyzer import Signature, SignatureAnalyzer
from core.tron_client import TronAPIClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdsa_scanner",
        description="ECDSA Сканер уязвимостей (TRON + BTC | CSV/TXT файлы и Bitcoin RPC)",
    )
    parser.add_argument("--cli", action="store_true", help="Запуск в консольном режиме (CLI)")
    parser.add_argument("-i", "--input", default="", help="Путь к входному CSV или TXT файлу")
    parser.add_argument(
        "--network",
        choices=["auto", "tron", "btc"],
        default="auto",
        help="Сеть для файлового режима (auto, tron, btc)",
    )
    parser.add_argument("--tron-api", default=TronAPIClient.DEFAULT_ENDPOINT, help="URL TRON API (TronGrid)")
    parser.add_argument("--tron-api-key", default="", help="Опциональный API-ключ TronGrid")
    parser.add_argument("--btc-rest", default=BTCRestClient.DEFAULT_ENDPOINT, help="URL публичного BTC REST API")
    parser.add_argument("--include-failed", action="store_true", help="Включать FAIL-транзакции из CSV")
    parser.add_argument("--filter-address", default="", help="Фильтровать CSV по указанному адресу")
    parser.add_argument("--max-items", type=int, default=0, help="Макс. число TX/адресов из файла (0 = все)")
    parser.add_argument("--max-tx-per-addr", type=int, default=200, help="Макс. транзакций на адрес из TXT")

    # Параметры Bitcoin Core RPC (режим сканирования блоков)
    parser.add_argument("-e", "--endpoint", default="http://127.0.0.1:8332", help="Bitcoin RPC URL")
    parser.add_argument("-u", "--username", default="", help="Логин RPC")
    parser.add_argument("-p", "--password", default="", help="Пароль RPC")
    parser.add_argument("-s", "--start-height", type=int, default=0, help="Начальная высота блока")
    parser.add_argument("-f", "--end-height", type=int, default=-1, help="Конечная высота блока (-1 = последний)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Количество потоков")
    parser.add_argument("-b", "--batch-size", type=int, default=10, help="Размер пакета")
    parser.add_argument("-r", "--rate-limit", type=int, default=6, help="Лимит запросов API/RPC в секунду")
    parser.add_argument("-d", "--database", default="ecdsa_scanner.db", help="Путь к SQLite БД")
    parser.add_argument("-c", "--cache-size", type=int, default=512, help="Размер кэша (МБ)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод")
    parser.add_argument("--dry-run", action="store_true", help="Тестовый прогон без записи в БД")
    return parser


def _run_cli_file_mode(args: argparse.Namespace) -> int:
    ds = load_input_file(args.input)
    print("ECDSA Сканер уязвимостей v3.0 [CLI // ФАЙЛ]")
    print("=" * 50)
    print(f"  Файл:           {ds.file_name}")
    print(f"  Формат:         {ds.kind_title_ru}")
    print(f"  Сеть (авто):    {ds.network} (выбрано: {args.network.upper()})")
    print(f"  Транзакций:     {len(ds.transactions)} | Адресов: {len(ds.addresses)}")
    print(f"  База данных:    {args.database} (dry-run: {'да' if args.dry_run else 'нет'})")
    print()

    def cli_log(level: str, msg: str) -> None:
        if level == "DEBUG" and not args.verbose:
            return
        print(f"[{utils.get_timestamp()}] [{level}] {msg}")

    tron_client = TronAPIClient(
        endpoint=args.tron_api,
        api_key=args.tron_api_key,
        rate_limit=args.rate_limit,
        logger=cli_log,
    )
    btc_rest = BTCRestClient(
        endpoint=args.btc_rest,
        rate_limit=args.rate_limit,
        logger=cli_log,
    )
    db = DatabaseManager(args.database, dry_run=args.dry_run)
    r_cache: LRUCache[str, List[Signature]] = LRUCache(max(1000, int(args.cache_size * 100)))

    def on_progress(st: ProcessingStats) -> None:
        total = max(1, st.total_blocks)
        pct = 100.0 * st.blocks_processed / total
        sys.stdout.write(
            f"\rПрогресс: {st.blocks_processed}/{st.total_blocks} ({pct:.1f}%) | "
            f"TX: {st.transactions_processed} | Подписей: {st.signatures_processed} | "
            f"Повторов R: {st.r_value_reuses_found} | Уязвимостей: {st.vulnerabilities_flagged}   "
        )
        sys.stdout.flush()

    processor = FileScanProcessor(
        dataset=ds,
        signature_analyzer=SignatureAnalyzer(),
        db_manager=db,
        r_value_cache=r_cache,
        network_override=args.network.upper(),
        tron_client=tron_client,
        btc_rest_client=btc_rest,
        threads=args.threads,
        only_success=not args.include_failed,
        filter_address=args.filter_address,
        max_items=args.max_items,
        max_tx_per_address=args.max_tx_per_addr,
        on_log=cli_log,
        on_progress=on_progress,
    )

    def handle_sig(_signum: int, _frame: Any) -> None:
        print("\nПолучен сигнал остановки, завершаем потоки...")
        processor.stop()

    signal.signal(signal.SIGINT, handle_sig)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_sig)

    t0 = time.monotonic()
    stats = processor.start_processing()
    elapsed = time.monotonic() - t0
    db.close()

    print("\n\nСканирование файла завершено!")
    print(f"  Время:                {utils.format_duration(elapsed)}")
    print(f"  Обработано объектов:  {stats.blocks_processed}")
    print(f"  Транзакций:           {stats.transactions_processed}")
    print(f"  Подписей ECDSA:       {stats.signatures_processed}")
    print(f"  Повторов R:           {stats.r_value_reuses_found}")
    print(f"  Зафиксировано угроз:  {stats.vulnerabilities_flagged}")
    return 0


def run_cli(args: argparse.Namespace) -> int:
    if args.input:
        return _run_cli_file_mode(args)

    print("ECDSA Сканер уязвимостей v3.0 [CLI // BTC RPC]")
    print("=" * 50)
    print(f"  RPC URL:        {args.endpoint}")
    print(f"  Диапазон:       {args.start_height} .. {'последний' if args.end_height == -1 else args.end_height}")
    print(f"  Потоки:         {args.threads}")
    print(f"  Лимит RPC:      {args.rate_limit} запр/с")
    print(f"  База данных:    {args.database}")
    print(f"  Dry-Run:        {'да' if args.dry_run else 'нет'}")
    print()

    def cli_log(level: str, msg: str) -> None:
        if level == "DEBUG" and not args.verbose:
            return
        print(f"[{utils.get_timestamp()}] [{level}] {msg}")

    rpc = RPCClient(
        endpoint=args.endpoint,
        username=args.username,
        password=args.password,
        rate_limit=args.rate_limit,
        batch_size=args.batch_size,
        logger=cli_log,
    )

    end_height = args.end_height
    if end_height == -1:
        cli_log("INFO", "Получение текущей высоты блокчейна...")
        end_height = rpc.get_block_count()
        cli_log("INFO", f"Текущая высота сети: {end_height}")

    if args.start_height < 0 or end_height < args.start_height:
        cli_log("ERROR", f"Некорректный диапазон блоков: {args.start_height} .. {end_height}")
        return 1

    db = DatabaseManager(args.database, dry_run=args.dry_run)
    cap = max(200, int(args.cache_size * 50))
    block_cache: LRUCache[int, Dict[str, Any]] = LRUCache(max(50, cap // 10))
    tx_cache: LRUCache[str, Dict[str, Any]] = LRUCache(cap)
    r_cache: LRUCache[str, List[Signature]] = LRUCache(cap * 2)

    analyzer = SignatureAnalyzer()

    def on_progress(st: ProcessingStats) -> None:
        total = max(1, st.total_blocks)
        pct = 100.0 * st.blocks_processed / total
        sys.stdout.write(
            f"\rПрогресс: {st.blocks_processed}/{st.total_blocks} ({pct:.1f}%) | "
            f"TX: {st.transactions_processed} | Подписей: {st.signatures_processed} | "
            f"Повторов R: {st.r_value_reuses_found} | Уязвимостей: {st.vulnerabilities_flagged}   "
        )
        sys.stdout.flush()

    processor = BlockProcessor(
        rpc_client=rpc,
        signature_analyzer=analyzer,
        db_manager=db,
        block_cache=block_cache,
        transaction_cache=tx_cache,
        r_value_cache=r_cache,
        threads=args.threads,
        batch_size=args.batch_size,
        on_log=cli_log,
        on_progress=on_progress,
    )

    def handle_sig(_signum: int, _frame: Any) -> None:
        print("\nПолучен сигнал остановки, корректно завершаем потоки...")
        processor.stop()

    signal.signal(signal.SIGINT, handle_sig)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_sig)

    t0 = time.monotonic()
    stats = processor.start_processing(args.start_height, end_height)
    elapsed = time.monotonic() - t0
    db.close()

    print("\n\nСканирование завершено!")
    print(f"  Время:                {utils.format_duration(elapsed)}")
    print(f"  Обработано блоков:    {stats.blocks_processed}")
    print(f"  Транзакций:           {stats.transactions_processed}")
    print(f"  Подписей ECDSA:       {stats.signatures_processed}")
    print(f"  Повторов R:           {stats.r_value_reuses_found}")
    print(f"  Зафиксировано угроз:  {stats.vulnerabilities_flagged}")
    rpc_s = rpc.get_stats()
    print(f"  RPC-запросов:         {rpc_s['total_requests']} (успешность: {rpc_s['success_rate']:.1f}%)")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        from ui.cyber_gui import launch_gui

        launch_gui()
        return 0

    parser = build_parser()
    args = parser.parse_args()
    if args.cli or args.input or len(sys.argv) > 1:
        return run_cli(args)

    from ui.cyber_gui import launch_gui

    launch_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
