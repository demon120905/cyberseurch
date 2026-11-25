"""Универсальный парсер входных файлов CSV (таблицы транзакций/подписей) и TXT (списки адресов/TXID)."""

from __future__ import annotations

import csv
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core import utils

# Возможные имена колонок в CSV (в нижнем регистре)
TX_HASH_COLS = ("txn hash", "txid", "tx_hash", "tx hash", "hash", "transaction hash", "transaction_hash", "tx")
BLOCK_COLS = ("block", "block_height", "block number", "height", "blocknum")
TIME_COLS = ("time (utc)", "time", "timestamp", "date", "datetime", "created_at")
TYPE_COLS = ("transaction type", "type", "contract type", "contract_type", "method name", "script_type")
FROM_COLS = ("from", "sender", "owner", "owner_address", "source", "from_address")
TO_COLS = ("to", "recipient", "to_address", "destination", "target")
TOKEN_COLS = ("token symbol", "symbol", "token", "asset", "currency")
AMOUNT_COLS = ("amount", "value", "qty", "quantity", "sum")
RESULT_COLS = ("result", "status", "tx_status", "state")
ADDR_ONLY_COLS = ("address", "wallet", "wallet_address", "addr")

# Для оффлайн CSV с готовыми подписями
R_COLS = ("r", "r_value", "sig_r")
S_COLS = ("s", "s_value", "sig_s")
Z_COLS = ("z", "z_value", "sighash", "msg_hash")
PUBKEY_COLS = ("pubkey", "public_key", "pub_key")


@dataclass
class ImportedTransaction:
    txid: str
    block: int = 0
    time_utc: str = ""
    tx_type: str = ""
    sender: str = ""
    recipient: str = ""
    token: str = ""
    amount: str = ""
    result: str = "SUCCESS"
    status: str = ""
    network: str = "AUTO"
    # Опциональные поля, если CSV уже содержит готовые ECDSA-компоненты
    r: str = ""
    s: str = ""
    z: str = ""
    pubkey: str = ""


@dataclass
class ImportedAddress:
    address: str
    network: str  # "TRON" или "BTC"
    label: str = ""


@dataclass
class LoadedDataset:
    file_path: str
    file_name: str
    file_ext: str  # ".csv" или ".txt"
    dataset_kind: str  # "csv_transactions" | "csv_signatures" | "csv_addresses" | "txt_addresses" | "txt_txids" | "txt_mixed"
    network: str  # "TRON" | "BTC" | "MIXED" | "UNKNOWN"
    transactions: List[ImportedTransaction] = field(default_factory=list)
    addresses: List[ImportedAddress] = field(default_factory=list)
    total_raw_rows: int = 0
    duplicates_removed: int = 0
    invalid_rows: int = 0
    success_count: int = 0
    fail_count: int = 0
    unique_senders: int = 0
    unique_recipients: int = 0
    primary_address: str = ""
    top_tx_types: List[Tuple[str, int]] = field(default_factory=list)
    columns: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def kind_title_ru(self) -> str:
        mapping = {
            "csv_transactions": "CSV: журнал транзакций",
            "csv_signatures": "CSV: готовые ECDSA-подписи (офлайн)",
            "csv_addresses": "CSV: список адресов",
            "txt_addresses": "TXT: список кошельков (адресов)",
            "txt_txids": "TXT: список хэшей транзакций (TXID)",
            "txt_mixed": "TXT: смешанный (адреса + TXID)",
        }
        return mapping.get(self.dataset_kind, "Неизвестный формат")

    @property
    def action_hint_ru(self) -> str:
        if self.dataset_kind == "csv_signatures":
            return "Подписи уже есть в файле — проверка повторов R выполнится мгновенно офлайн."
        if self.dataset_kind in ("csv_transactions", "txt_txids"):
            return (
                f"Из файла извлечены хэши транзакций ({len(self.transactions)} шт.). "
                f"При запуске сканер загрузит подписи каждой транзакции из сети {self.network} и проверит повторы R."
            )
        if self.dataset_kind in ("txt_addresses", "csv_addresses"):
            return (
                f"Из файла извлечены адреса кошельков ({len(self.addresses)} шт.). "
                f"При запуске сканер запросит исходящие транзакции каждого адреса в сети {self.network} и проверит их подписи."
            )
        if self.dataset_kind == "txt_mixed":
            return (
                f"Найдено адресов: {len(self.addresses)} и TXID: {len(self.transactions)}. "
                f"Сканер проверит и указанные транзакции, и историю адресов."
            )
        return "Загрузите корректный CSV или TXT файл."


def _read_text_auto_encoding(file_path: str) -> str:
    """Читает файл, автоматически подбирая кодировку (UTF-8 BOM / UTF-8 / Windows-1251 / Latin-1)."""
    with open(file_path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "cp1251", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _clean_cell(value: Optional[str]) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if s in ("'-", "-", "—", "N/A", "null", "None"):
        return ""
    return s


def _find_column(fieldnames_lower: Dict[str, str], candidates: Tuple[str, ...]) -> Optional[str]:
    for cand in candidates:
        if cand in fieldnames_lower:
            return fieldnames_lower[cand]
    return None


def _detect_delimiter(sample: str) -> str:
    first_lines = "\n".join(sample.splitlines()[:10])
    try:
        dialect = csv.Sniffer().sniff(first_lines, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        counts = {",": first_lines.count(","), ";": first_lines.count(";"), "\t": first_lines.count("\t")}
        best = max(counts, key=lambda k: counts[k])
        return best if counts[best] > 0 else ","


def _parse_block_int(val: str) -> int:
    cleaned = re.sub(r"[^0-9]", "", val or "")
    return int(cleaned) if cleaned else 0


def _infer_network_from_counts(tron_hits: int, btc_hits: int) -> str:
    if tron_hits > 0 and btc_hits > 0:
        return "TRON" if tron_hits >= btc_hits * 3 else ("BTC" if btc_hits >= tron_hits * 3 else "MIXED")
    if tron_hits > 0:
        return "TRON"
    if btc_hits > 0:
        return "BTC"
    return "UNKNOWN"


def load_input_file(file_path: str) -> LoadedDataset:
    """Загружает и автоматически распознаёт CSV или TXT файл."""
    if not file_path or not os.path.isfile(file_path):
        raise FileNotFoundError(f"Файл не найден: {file_path}")

    file_name = os.path.basename(file_path)
    _, ext = os.path.splitext(file_name)
    ext_lower = ext.lower()

    content = _read_text_auto_encoding(file_path)
    if not content.strip():
        raise ValueError("Выбранный файл пуст.")

    # Определяем, парсить как CSV или как TXT
    if ext_lower == ".csv":
        return _parse_csv(file_path, file_name, ext_lower, content)
    if ext_lower == ".txt":
        return _parse_txt(file_path, file_name, ext_lower, content)

    # Если расширение нестандартное — смотрим на первую строку
    first_line = content.splitlines()[0]
    if ("," in first_line or ";" in first_line or "\t" in first_line) and any(
        kw in first_line.lower() for kw in ("hash", "txid", "block", "from", "address")
    ):
        return _parse_csv(file_path, file_name, ext_lower or ".csv", content)
    return _parse_txt(file_path, file_name, ext_lower or ".txt", content)


def _parse_csv(file_path: str, file_name: str, ext_lower: str, content: str) -> LoadedDataset:
    delimiter = _detect_delimiter(content)
    lines = content.splitlines()
    reader = csv.DictReader(lines, delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("CSV-файл не содержит заголовков колонок.")

    clean_fields = [f.strip() for f in reader.fieldnames if f is not None]
    field_map = {f.strip().lower(): f for f in reader.fieldnames if f is not None}

    col_tx = _find_column(field_map, TX_HASH_COLS)
    col_block = _find_column(field_map, BLOCK_COLS)
    col_time = _find_column(field_map, TIME_COLS)
    col_type = _find_column(field_map, TYPE_COLS)
    col_from = _find_column(field_map, FROM_COLS)
    col_to = _find_column(field_map, TO_COLS)
    col_token = _find_column(field_map, TOKEN_COLS)
    col_amount = _find_column(field_map, AMOUNT_COLS)
    col_result = _find_column(field_map, RESULT_COLS)
    col_status = field_map.get("status")
    col_addr = _find_column(field_map, ADDR_ONLY_COLS)

    col_r = _find_column(field_map, R_COLS)
    col_s = _find_column(field_map, S_COLS)
    col_z = _find_column(field_map, Z_COLS)
    col_pk = _find_column(field_map, PUBKEY_COLS)

    # Вариант 1: CSV со списком адресов (нет колонки TX hash, но есть address)
    if not col_tx and col_addr:
        return _parse_csv_addresses(file_path, file_name, ext_lower, clean_fields, reader, col_addr)

    # Вариант 2: CSV вообще без ожидаемых заголовков -> попробуем извлечь как TXT
    if not col_tx and not col_r:
        ds = _parse_txt(file_path, file_name, ext_lower, content)
        ds.warnings.append("Заголовки транзакций в CSV не распознаны — файл разобран построчно.")
        return ds

    is_offline_sigs = bool(col_r and col_s)
    seen_txids: set[str] = set()
    transactions: List[ImportedTransaction] = []
    addr_counter: Counter[str] = Counter()
    senders_set: set[str] = set()
    recipients_set: set[str] = set()
    type_counter: Counter[str] = Counter()

    total_rows = 0
    duplicates = 0
    invalid = 0
    success_cnt = 0
    fail_cnt = 0
    tron_hits = 0
    btc_hits = 0

    for row in reader:
        if not row:
            continue
        total_rows += 1

        txid = _clean_cell(row.get(col_tx)) if col_tx else ""
        if txid.startswith(("0x", "0X")):
            txid = txid[2:]
        txid_low = txid.lower()

        r_val = utils.normalize_hex_32(_clean_cell(row.get(col_r))) if col_r else ""
        s_val = utils.normalize_hex_32(_clean_cell(row.get(col_s))) if col_s else ""
        z_val = utils.normalize_hex_32(_clean_cell(row.get(col_z))) if col_z else ""
        pk_val = _clean_cell(row.get(col_pk)) if col_pk else ""

        if is_offline_sigs:
            if not (r_val and s_val):
                invalid += 1
                continue
            if not txid_low:
                txid_low = f"row_{total_rows:06d}"
        else:
            if not utils.is_txid_hex(txid_low):
                invalid += 1
                continue
            if txid_low in seen_txids:
                duplicates += 1
                continue
            seen_txids.add(txid_low)

        sender = _clean_cell(row.get(col_from)) if col_from else ""
        if not sender and col_addr:
            sender = _clean_cell(row.get(col_addr))
        recipient = _clean_cell(row.get(col_to)) if col_to else ""

        row_net = ""
        for candidate_addr in (sender, recipient):
            if not candidate_addr:
                continue
            net = utils.detect_address_network(candidate_addr)
            if net == "TRON":
                tron_hits += 1
                row_net = "TRON"
            elif net == "BTC":
                btc_hits += 1
                row_net = row_net or "BTC"

        if sender:
            senders_set.add(sender)
            addr_counter[sender] += 1
        if recipient:
            recipients_set.add(recipient)
            addr_counter[recipient] += 1

        tx_type = _clean_cell(row.get(col_type)) if col_type else ""
        if tx_type:
            type_counter[tx_type] += 1

        res_raw = _clean_cell(row.get(col_result)) if col_result else "SUCCESS"
        res_upper = res_raw.upper() if res_raw else "SUCCESS"
        if res_upper in ("FAIL", "FAILED", "REVERT", "ERROR", "FALSE"):
            fail_cnt += 1
        else:
            success_cnt += 1

        token = _clean_cell(row.get(col_token)) if col_token else ""
        amount = _clean_cell(row.get(col_amount)) if col_amount else ""
        status = _clean_cell(row.get(col_status)) if col_status else ""
        block_num = _parse_block_int(_clean_cell(row.get(col_block))) if col_block else 0
        time_utc = _clean_cell(row.get(col_time)) if col_time else ""

        transactions.append(
            ImportedTransaction(
                txid=txid_low,
                block=block_num,
                time_utc=time_utc,
                tx_type=tx_type,
                sender=sender,
                recipient=recipient,
                token=token,
                amount=amount,
                result=res_upper,
                status=status,
                network=row_net or "AUTO",
                r=r_val,
                s=s_val,
                z=z_val or txid_low,
                pubkey=pk_val,
            )
        )

    network = _infer_network_from_counts(tron_hits, btc_hits)
    # Если сеть определена глобально — проставляем в строки с AUTO
    if network in ("TRON", "BTC"):
        for tx in transactions:
            if tx.network == "AUTO":
                tx.network = network

    primary_addr = addr_counter.most_common(1)[0][0] if addr_counter else ""

    return LoadedDataset(
        file_path=file_path,
        file_name=file_name,
        file_ext=ext_lower,
        dataset_kind="csv_signatures" if is_offline_sigs else "csv_transactions",
        network=network,
        transactions=transactions,
        total_raw_rows=total_rows,
        duplicates_removed=duplicates,
        invalid_rows=invalid,
        success_count=success_cnt,
        fail_count=fail_cnt,
        unique_senders=len(senders_set),
        unique_recipients=len(recipients_set),
        primary_address=primary_addr,
        top_tx_types=type_counter.most_common(5),
        columns=clean_fields,
    )


def _parse_csv_addresses(
    file_path: str,
    file_name: str,
    ext_lower: str,
    columns: List[str],
    reader: csv.DictReader,
    col_addr: str,
) -> LoadedDataset:
    addresses: List[ImportedAddress] = []
    seen: set[str] = set()
    total_rows = 0
    duplicates = 0
    invalid = 0
    tron_hits = 0
    btc_hits = 0

    for row in reader:
        if not row:
            continue
        total_rows += 1
        addr = _clean_cell(row.get(col_addr))
        net = utils.detect_address_network(addr)
        if not net:
            invalid += 1
            continue
        if addr in seen:
            duplicates += 1
            continue
        seen.add(addr)
        if net == "TRON":
            tron_hits += 1
        else:
            btc_hits += 1
        addresses.append(ImportedAddress(address=addr, network=net))

    return LoadedDataset(
        file_path=file_path,
        file_name=file_name,
        file_ext=ext_lower,
        dataset_kind="csv_addresses",
        network=_infer_network_from_counts(tron_hits, btc_hits),
        addresses=addresses,
        total_raw_rows=total_rows,
        duplicates_removed=duplicates,
        invalid_rows=invalid,
        primary_address=addresses[0].address if addresses else "",
        columns=columns,
    )


def _parse_txt(file_path: str, file_name: str, ext_lower: str, content: str) -> LoadedDataset:
    addresses: List[ImportedAddress] = []
    transactions: List[ImportedTransaction] = []
    seen_addrs: set[str] = set()
    seen_txids: set[str] = set()

    total_rows = 0
    duplicates = 0
    invalid = 0
    tron_hits = 0
    btc_hits = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        total_rows += 1
        # Убираем хвостовой комментарий
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        tokens = [t.strip() for t in re.split(r"[\s,;|]+", line) if t.strip()]
        line_matched = False
        for token in tokens:
            net = utils.detect_address_network(token)
            if net:
                line_matched = True
                if token in seen_addrs:
                    duplicates += 1
                else:
                    seen_addrs.add(token)
                    if net == "TRON":
                        tron_hits += 1
                    else:
                        btc_hits += 1
                    addresses.append(ImportedAddress(address=token, network=net))
                continue

            if utils.is_txid_hex(token):
                line_matched = True
                tx_low = token[2:].lower() if token.startswith(("0x", "0X")) else token.lower()
                if tx_low in seen_txids:
                    duplicates += 1
                else:
                    seen_txids.add(tx_low)
                    transactions.append(ImportedTransaction(txid=tx_low, network="AUTO"))

        if not line_matched:
            invalid += 1

    if addresses and transactions:
        kind = "txt_mixed"
    elif addresses:
        kind = "txt_addresses"
    elif transactions:
        kind = "txt_txids"
    else:
        raise ValueError(
            "В TXT-файле не найдено ни одного корректного адреса (TRON T... / BTC 1..., 3..., bc1...) "
            "или 64-символьного хэша транзакции (TXID)."
        )

    network = _infer_network_from_counts(tron_hits, btc_hits)
    return LoadedDataset(
        file_path=file_path,
        file_name=file_name,
        file_ext=ext_lower,
        dataset_kind=kind,
        network=network,
        transactions=transactions,
        addresses=addresses,
        total_raw_rows=total_rows,
        duplicates_removed=duplicates,
        invalid_rows=invalid,
        primary_address=addresses[0].address if addresses else "",
    )
