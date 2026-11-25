"""Криптографические, адресные и вспомогательные утилиты для BTC и TRON ECDSA сканера."""

from __future__ import annotations

import hashlib
import re
import struct
from datetime import datetime
from typing import Any, Dict, List

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_RE = re.compile(r"^(bc1|tb1)[0-9a-z]{25,87}$", re.IGNORECASE)


def is_hex_string(value: str) -> bool:
    if not value or len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def hex_to_bytes(hex_str: str) -> bytes:
    cleaned = hex_str.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def normalize_hex_32(hex_str: str) -> str:
    """Нормализует hex-строку скаляра (r/s/z) до 64 символов (32 байта)."""
    cleaned = hex_str.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) > 64:
        cleaned = cleaned.lstrip("0")
    if len(cleaned) > 64:
        return ""
    if not cleaned:
        return ""
    try:
        int(cleaned, 16)
    except ValueError:
        return ""
    return cleaned.zfill(64)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ripemd160(data: bytes) -> bytes:
    """Чистая реализация RIPEMD-160 (совместима с OpenSSL 3+ на Windows и Linux)."""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    r_l = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    r_r = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    s_l = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    s_r = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]

    msg = bytearray(data)
    orig_len_bits = len(msg) * 8
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    for offset in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[offset : offset + 64])
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4

        for j in range(80):
            if j < 16:
                fl = bl ^ cl ^ dl
                kl = 0x00000000
                fr = br ^ (cr | (~dr & 0xFFFFFFFF))
                kr = 0x50A28BE6
            elif j < 32:
                fl = (bl & cl) | ((~bl & 0xFFFFFFFF) & dl)
                kl = 0x5A827999
                fr = (br & dr) | (cr & (~dr & 0xFFFFFFFF))
                kr = 0x5C4DD124
            elif j < 48:
                fl = (bl | (~cl & 0xFFFFFFFF)) ^ dl
                kl = 0x6ED9EBA1
                fr = (br | (~cr & 0xFFFFFFFF)) ^ dr
                kr = 0x6D703EF3
            elif j < 64:
                fl = (bl & dl) | (cl & (~dl & 0xFFFFFFFF))
                kl = 0x8F1BBCDC
                fr = (br & cr) | ((~br & 0xFFFFFFFF) & dr)
                kr = 0x7A6D76E9
            else:
                fl = bl ^ (cl | (~dl & 0xFFFFFFFF))
                kl = 0xA953FD4E
                fr = br ^ cr ^ dr
                kr = 0x00000000

            t = (_rol32((al + fl + x[r_l[j]] + kl) & 0xFFFFFFFF, s_l[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t

            t = (_rol32((ar + fr + x[r_r[j]] + kr) & 0xFFFFFFFF, s_r[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t

        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t

    return struct.pack("<5I", h0, h1, h2, h3, h4)


def base58_encode(data: bytes) -> str:
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break
    num = int.from_bytes(data, "big")
    chars: List[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return ("1" * leading_zeros) + "".join(reversed(chars))


def base58_decode(encoded: str) -> bytes:
    leading_zeros = 0
    for ch in encoded:
        if ch == "1":
            leading_zeros += 1
        else:
            break
    num = 0
    for ch in encoded:
        idx = BASE58_ALPHABET.find(ch)
        if idx == -1:
            raise ValueError(f"Недопустимый символ Base58: {ch}")
        num = num * 58 + idx
    byte_len = (num.bit_length() + 7) // 8
    raw = num.to_bytes(byte_len, "big") if byte_len > 0 else b""
    return (b"\x00" * leading_zeros) + raw


def base58check_decode(encoded: str) -> bytes:
    raw = base58_decode(encoded)
    if len(raw) < 5:
        raise ValueError("Слишком короткий Base58Check адрес")
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("Некорректная контрольная сумма Base58Check")
    return payload


def is_valid_tron_address(address: str) -> bool:
    """Проверяет TRON Base58Check адрес (начинается с T, 34 символа, байт версии 0x41)."""
    addr = address.strip()
    if len(addr) != 34 or not addr.startswith("T"):
        return False
    try:
        payload = base58check_decode(addr)
        return len(payload) == 21 and payload[0] == 0x41
    except Exception:
        return False


def tron_hex_to_base58(hex_addr: str) -> str:
    """Конвертирует TRON hex-адрес (41... или 20-байтовый) в Base58Check T-адрес."""
    cleaned = hex_addr.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 40:
        cleaned = "41" + cleaned
    if len(cleaned) != 42 or not is_hex_string(cleaned):
        return hex_addr
    payload = bytes.fromhex(cleaned)
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def tron_base58_to_hex(address: str) -> str:
    """Конвертирует TRON Base58Check адрес (T...) в 42-символьный hex (41...)."""
    payload = base58check_decode(address.strip())
    if len(payload) != 21 or payload[0] != 0x41:
        raise ValueError(f"Некорректный TRON-адрес: {address}")
    return payload.hex()


def is_valid_btc_address(address: str) -> bool:
    """Проверяет Bitcoin адрес (Base58Check 1.../3... или Bech32 bc1...)."""
    addr = address.strip()
    if not addr:
        return False
    if BECH32_RE.match(addr):
        return True
    if addr[0] in ("1", "3", "m", "n", "2") and 26 <= len(addr) <= 35:
        try:
            payload = base58check_decode(addr)
            return len(payload) == 21 and payload[0] in (0x00, 0x05, 0x6F, 0xC4)
        except Exception:
            return False
    return False


def is_txid_hex(value: str) -> bool:
    """Проверяет, является ли строка 64-символьным hex TXID."""
    s = value.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return len(s) == 64 and is_hex_string(s)


def detect_address_network(address: str) -> str:
    """Возвращает 'TRON', 'BTC' или '' для произвольного адреса."""
    if is_valid_tron_address(address):
        return "TRON"
    if is_valid_btc_address(address):
        return "BTC"
    return ""


def pubkey_to_address(pubkey: bytes, version_byte: int = 0x00) -> str:
    h160 = ripemd160(sha256(pubkey))
    return pubkey_hash_to_address(h160, version_byte)


def pubkey_hash_to_address(pubkey_hash: bytes, version_byte: int = 0x00) -> str:
    versioned = bytes([version_byte]) + pubkey_hash
    checksum = double_sha256(versioned)[:4]
    return base58_encode(versioned + checksum)


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def serialize_transaction_for_sighash(
    tx: Dict[str, Any],
    input_index: int,
    prevout_script_pubkey_hex: str,
) -> bytes:
    """Бинарная сериализация транзакции Bitcoin для расчёта SIGHASH_ALL."""
    out = bytearray()

    version = int(tx.get("version", 1))
    out += struct.pack("<i", version)

    vins = tx.get("vin", [])
    out += encode_varint(len(vins))

    prevout_script = hex_to_bytes(prevout_script_pubkey_hex) if prevout_script_pubkey_hex else b""

    for idx, vin in enumerate(vins):
        txid_hex = str(vin.get("txid", "00" * 32))
        txid_bytes = hex_to_bytes(txid_hex)
        if len(txid_bytes) != 32:
            txid_bytes = txid_bytes.rjust(32, b"\x00")[:32]
        out += txid_bytes[::-1]

        vout_idx = int(vin.get("vout", 0))
        out += struct.pack("<I", vout_idx)

        if idx == input_index:
            out += encode_varint(len(prevout_script))
            out += prevout_script
        else:
            out += b"\x00"

        seq = int(vin.get("sequence", 0xFFFFFFFF)) & 0xFFFFFFFF
        out += struct.pack("<I", seq)

    vouts = tx.get("vout", [])
    out += encode_varint(len(vouts))

    for vout in vouts:
        val_btc = float(vout.get("value", 0.0))
        satoshis = int(round(val_btc * 100_000_000))
        out += struct.pack("<q", satoshis)

        spk_hex = ""
        if isinstance(vout.get("scriptPubKey"), dict):
            spk_hex = str(vout["scriptPubKey"].get("hex", ""))
        spk_bytes = hex_to_bytes(spk_hex) if spk_hex else b""
        out += encode_varint(len(spk_bytes))
        out += spk_bytes

    locktime = int(tx.get("locktime", 0)) & 0xFFFFFFFF
    out += struct.pack("<I", locktime)

    # SIGHASH_ALL (0x01000000 в little-endian)
    out += struct.pack("<I", 1)
    return bytes(out)


def compute_transaction_hash(
    tx: Dict[str, Any],
    input_index: int,
    prevout_script_pubkey_hex: str,
) -> str:
    serialized = serialize_transaction_for_sighash(tx, input_index, prevout_script_pubkey_hex)
    return double_sha256(serialized).hex()


def format_duration(seconds: float) -> str:
    total_ms = max(0, int(seconds * 1000))
    hours, rem = divmod(total_ms, 3_600_000)
    minutes, rem = divmod(rem, 60_000)
    secs, ms = divmod(rem, 1000)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    if minutes > 0:
        return f"{minutes:02d}:{secs:02d}.{ms // 100}"
    return f"{secs}.{ms // 10:02d} с"


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
