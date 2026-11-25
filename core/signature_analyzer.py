"""Анализатор ECDSA-подписей в транзакциях Bitcoin (RPC / Esplora) и TRON (TronGrid / FullNode)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core import utils


@dataclass
class Signature:
    txid: str
    block_height: int
    address: str
    pubkey: str
    r: str
    s: str
    z: str
    script_type: str
    input_index: int


def _parse_script_pushes(script_bytes: bytes) -> List[bytes]:
    """Разбирает Bitcoin scriptSig на последовательность push-элементов."""
    pushes: List[bytes] = []
    pos = 0
    n = len(script_bytes)
    while pos < n:
        op = script_bytes[pos]
        pos += 1
        if 1 <= op <= 0x4B:
            if pos + op > n:
                break
            pushes.append(script_bytes[pos : pos + op])
            pos += op
        elif op == 0x4C:  # OP_PUSHDATA1
            if pos >= n:
                break
            ln = script_bytes[pos]
            pos += 1
            if pos + ln > n:
                break
            pushes.append(script_bytes[pos : pos + ln])
            pos += ln
        elif op == 0x4D:  # OP_PUSHDATA2
            if pos + 2 > n:
                break
            ln = int.from_bytes(script_bytes[pos : pos + 2], "little")
            pos += 2
            if pos + ln > n:
                break
            pushes.append(script_bytes[pos : pos + ln])
            pos += ln
        elif op == 0x00:
            pushes.append(b"")
        else:
            # Не push-опкод — пропускаем
            continue
    return pushes


def _is_pubkey_bytes(data: bytes) -> bool:
    if len(data) == 33 and data[0] in (0x02, 0x03):
        return True
    if len(data) == 65 and data[0] == 0x04:
        return True
    return False


def _extract_pubkeys_from_redeem_script(script: bytes) -> List[bytes]:
    """Извлекает публичные ключи (33 или 65 байт) из multisig redeemScript / witnessScript."""
    return [p for p in _parse_script_pushes(script) if _is_pubkey_bytes(p)]


class SignatureAnalyzer:
    """Извлекает ECDSA-подписи (r, s, z) и идентификатор подписанта из транзакций BTC и TRON."""

    def analyze_transaction(
        self,
        tx: Dict[str, Any],
        block_height: int,
        filter_address: str = "",
    ) -> List[Signature]:
        """Анализирует Bitcoin Core JSON-RPC транзакцию (P2PKH, P2SH, Multisig, SegWit, P2WSH)."""
        signatures: List[Signature] = []

        vins = tx.get("vin")
        txid = tx.get("txid")
        if not isinstance(vins, list) or not isinstance(txid, str):
            return signatures

        if len(txid) != 64 or not utils.is_hex_string(txid):
            return signatures

        flt_low = filter_address.strip().lower()

        for idx, vin in enumerate(vins):
            if not isinstance(vin, dict) or "coinbase" in vin:
                continue

            # Если задан фильтр адреса и известен адрес prevout — пропускаем чужие входы
            prevout_addr = str(vin.get("prevout_address", "")).strip()
            if flt_low and prevout_addr and prevout_addr.lower() != flt_low:
                continue

            extracted_pairs: List[Tuple[bytes, bytes, str]] = []  # (sig_der, pubkey_bytes, script_type)

            # 1) Проверка SegWit witness (P2WPKH, P2SH-P2WPKH, P2WSH multisig)
            witness = vin.get("txinwitness")
            if isinstance(witness, list) and len(witness) >= 2:
                w_bytes: List[bytes] = []
                for w in witness:
                    try:
                        w_bytes.append(utils.hex_to_bytes(str(w)) if str(w) else b"")
                    except Exception:
                        w_bytes.append(b"")

                # Стандартный P2WPKH: [sig_der, pubkey]
                if len(w_bytes) == 2 and len(w_bytes[0]) >= 8 and w_bytes[0][0] == 0x30 and _is_pubkey_bytes(w_bytes[1]):
                    extracted_pairs.append((w_bytes[0], w_bytes[1], "segwit"))
                else:
                    # P2WSH / Multisig: [ "", sig1, sig2, ..., witnessScript ]
                    der_sigs = [wb for wb in w_bytes[:-1] if len(wb) >= 8 and wb[0] == 0x30]
                    if der_sigs:
                        redeem_pks = _extract_pubkeys_from_redeem_script(w_bytes[-1]) if w_bytes else []
                        for s_i, sig_b in enumerate(der_sigs):
                            pk_b = redeem_pks[s_i] if s_i < len(redeem_pks) else (redeem_pks[0] if redeem_pks else b"")
                            extracted_pairs.append((sig_b, pk_b, "segwit_multisig"))

            # 2) Разбор scriptSig (P2PKH / P2SH / Multisig)
            if not extracted_pairs:
                script_sig = vin.get("scriptSig")
                if isinstance(script_sig, dict):
                    script_hex = str(script_sig.get("hex", ""))
                    if script_hex and utils.is_hex_string(script_hex):
                        script_bytes = utils.hex_to_bytes(script_hex)
                        pushes = _parse_script_pushes(script_bytes)

                        der_sigs = [p for p in pushes if 8 <= len(p) <= 75 and p[0] == 0x30]
                        pks = [p for p in pushes if _is_pubkey_bytes(p)]

                        if der_sigs and pks:
                            st = "p2pkh"
                            if self.is_p2sh(script_bytes):
                                st = "p2sh"
                            elif self.is_multisig(script_bytes):
                                st = "multisig"
                            elif self.is_segwit(script_bytes):
                                st = "segwit"
                            for s_i, sig_b in enumerate(der_sigs):
                                pk_b = pks[s_i] if s_i < len(pks) else pks[0]
                                extracted_pairs.append((sig_b, pk_b, st))
                        elif der_sigs and len(pushes) >= 2:
                            # P2SH Multisig: последний push — redeemScript
                            redeem_pks = _extract_pubkeys_from_redeem_script(pushes[-1])
                            for s_i, sig_b in enumerate(der_sigs):
                                pk_b = redeem_pks[s_i] if s_i < len(redeem_pks) else (redeem_pks[0] if redeem_pks else b"")
                                extracted_pairs.append((sig_b, pk_b, "p2sh_multisig"))
                        elif der_sigs and len(pushes) == 1:
                            # P2PK (ранние транзакции Bitcoin): только подпись в scriptSig
                            extracted_pairs.append((der_sigs[0], b"", "p2pk"))

            for sub_i, (sig_der, pubkey_bytes, script_type) in enumerate(extracted_pairs):
                r_hex, s_hex = self.extract_signature_components(sig_der)
                if not r_hex or not s_hex:
                    continue

                z_hex = self.compute_message_hash(tx, idx, pubkey_bytes or None)
                if not z_hex:
                    continue

                if prevout_addr:
                    address = prevout_addr
                elif pubkey_bytes:
                    address = utils.pubkey_to_address(pubkey_bytes)
                else:
                    address = "UNKNOWN_BTC"

                if flt_low and address.lower() != flt_low:
                    continue

                pk_hex = pubkey_bytes.hex() if pubkey_bytes else f"btc:{address}"
                signatures.append(
                    Signature(
                        txid=txid,
                        block_height=block_height,
                        address=address,
                        pubkey=pk_hex,
                        r=r_hex,
                        s=s_hex,
                        z=z_hex,
                        script_type=script_type,
                        input_index=idx * 100 + sub_i if sub_i > 0 else idx,
                    )
                )

        return signatures

    def analyze_esplora_btc_tx(self, tx: Dict[str, Any], filter_address: str = "") -> List[Signature]:
        """Преобразует Esplora (Blockstream/Mempool) JSON транзакцию в стандартный формат и извлекает подписи."""
        if not isinstance(tx, dict) or not tx.get("txid"):
            return []
        status = tx.get("status", {})
        block_height = int(status.get("block_height", 0) or 0) if isinstance(status, dict) else 0

        converted_vins: List[Dict[str, Any]] = []
        for vin in tx.get("vin", []):
            if not isinstance(vin, dict) or vin.get("is_coinbase"):
                continue
            item: Dict[str, Any] = {
                "txid": vin.get("txid", "00" * 32),
                "vout": int(vin.get("vout", 0) or 0),
                "sequence": int(vin.get("sequence", 0xFFFFFFFF) or 0xFFFFFFFF),
            }
            if vin.get("scriptsig"):
                item["scriptSig"] = {"hex": str(vin["scriptsig"])}
            if isinstance(vin.get("witness"), list):
                item["txinwitness"] = [str(w) for w in vin["witness"]]
            prevout = vin.get("prevout")
            if isinstance(prevout, dict):
                if prevout.get("scriptpubkey"):
                    item["prevOut"] = {"scriptPubKey": {"hex": str(prevout["scriptpubkey"])}}
                if prevout.get("scriptpubkey_address"):
                    item["prevout_address"] = str(prevout["scriptpubkey_address"])
            converted_vins.append(item)

        converted_vouts: List[Dict[str, Any]] = []
        for vout in tx.get("vout", []):
            if not isinstance(vout, dict):
                continue
            sat = int(vout.get("value", 0) or 0)
            converted_vouts.append(
                {
                    "value": sat / 100_000_000.0,
                    "scriptPubKey": {"hex": str(vout.get("scriptpubkey", ""))},
                }
            )

        normalized = {
            "txid": str(tx["txid"]),
            "version": int(tx.get("version", 1) or 1),
            "locktime": int(tx.get("locktime", 0) or 0),
            "vin": converted_vins,
            "vout": converted_vouts,
        }
        return self.analyze_transaction(normalized, block_height=block_height, filter_address=filter_address)

    def analyze_tron_transaction(
        self,
        tx: Dict[str, Any],
        block_height: int = 0,
        fallback_address: str = "",
    ) -> List[Signature]:
        """
        Извлекает ECDSA-подписи (r, s, z) из транзакции TRON.
        В TRON: txID = sha256(raw_data) (32 байта = z), signature[] = 65-байтовые hex-строки (r[32] + s[32] + v[1]).
        """
        signatures: List[Signature] = []
        if not isinstance(tx, dict):
            return signatures

        txid = str(tx.get("txID") or tx.get("txid") or "").strip().lower()
        if not utils.is_txid_hex(txid):
            return signatures

        sig_list = tx.get("signature")
        if not isinstance(sig_list, list) or not sig_list:
            return signatures

        b_height = int(tx.get("blockNumber") or block_height or 0)

        owner_addr = ""
        contract_type = "TRON"
        raw_data = tx.get("raw_data")
        if isinstance(raw_data, dict):
            contracts = raw_data.get("contract")
            if isinstance(contracts, list) and contracts:
                c0 = contracts[0]
                if isinstance(c0, dict):
                    contract_type = str(c0.get("type") or "TRON")
                    val = c0.get("parameter", {}).get("value", {})
                    if isinstance(val, dict):
                        raw_owner = str(val.get("owner_address") or val.get("from") or "").strip()
                        if raw_owner:
                            if utils.is_valid_tron_address(raw_owner):
                                owner_addr = raw_owner
                            else:
                                owner_addr = utils.tron_hex_to_base58(raw_owner)

        address = owner_addr or fallback_address or "UNKNOWN_TRON"
        signer_id = f"tron:{address}"

        for idx, sig_item in enumerate(sig_list):
            sig_hex = str(sig_item or "").strip().lower()
            if sig_hex.startswith("0x"):
                sig_hex = sig_hex[2:]
            if len(sig_hex) not in (128, 130) or not utils.is_hex_string(sig_hex):
                continue
            r_hex = utils.normalize_hex_32(sig_hex[:64])
            s_hex = utils.normalize_hex_32(sig_hex[64:128])
            if not r_hex or not s_hex:
                continue

            signatures.append(
                Signature(
                    txid=txid,
                    block_height=b_height,
                    address=address,
                    pubkey=signer_id,
                    r=r_hex,
                    s=s_hex,
                    z=txid,
                    script_type=f"tron:{contract_type}",
                    input_index=idx,
                )
            )

        return signatures

    def extract_signature_components(self, sig_der: bytes) -> Tuple[str, str]:
        """Извлекает (r, s) из DER-подписи (с учётом опционального байта sighash в конце)."""
        if len(sig_der) < 8 or sig_der[0] != 0x30:
            return "", ""

        total_len = sig_der[1]
        if total_len + 2 not in (len(sig_der), len(sig_der) - 1):
            return "", ""

        der_end = total_len + 2
        pos = 2

        if pos + 2 > der_end or sig_der[pos] != 0x02:
            return "", ""
        pos += 1
        r_len = sig_der[pos]
        pos += 1
        if r_len == 0 or pos + r_len > der_end:
            return "", ""
        r_bytes = sig_der[pos : pos + r_len]
        pos += r_len
        while len(r_bytes) > 1 and r_bytes[0] == 0x00:
            r_bytes = r_bytes[1:]
        if not r_bytes:
            return "", ""

        if pos + 2 > der_end or sig_der[pos] != 0x02:
            return "", ""
        pos += 1
        s_len = sig_der[pos]
        pos += 1
        if s_len == 0 or pos + s_len > der_end:
            return "", ""
        s_bytes = sig_der[pos : pos + s_len]
        while len(s_bytes) > 1 and s_bytes[0] == 0x00:
            s_bytes = s_bytes[1:]
        if not s_bytes:
            return "", ""

        r_hex = utils.normalize_hex_32(r_bytes.hex())
        s_hex = utils.normalize_hex_32(s_bytes.hex())
        if not r_hex or not s_hex:
            return "", ""
        return r_hex, s_hex

    def get_prevout_script_pubkey(
        self, tx: Dict[str, Any], input_index: int, pubkey_bytes: Optional[bytes] = None
    ) -> str:
        vins = tx.get("vin", [])
        if input_index >= len(vins):
            return ""
        vin = vins[input_index]
        if not isinstance(vin, dict):
            return ""

        prev_out = vin.get("prevOut")
        if isinstance(prev_out, dict):
            spk = prev_out.get("scriptPubKey")
            if isinstance(spk, dict) and spk.get("hex"):
                return str(spk["hex"])

        spk = vin.get("scriptPubKey")
        if isinstance(spk, dict) and spk.get("hex"):
            return str(spk["hex"])

        if pubkey_bytes:
            h160 = utils.ripemd160(utils.sha256(pubkey_bytes))
            return (b"\x76\xa9\x14" + h160 + b"\x88\xac").hex()

        return ""

    def compute_message_hash(
        self, tx: Dict[str, Any], input_index: int, pubkey_bytes: Optional[bytes] = None
    ) -> str:
        try:
            prevout_spk = self.get_prevout_script_pubkey(tx, input_index, pubkey_bytes)
            if prevout_spk:
                return utils.compute_transaction_hash(tx, input_index, prevout_spk)

            parts: List[str] = [str(tx.get("version", 1))]
            vins = tx.get("vin", [])
            parts.append(str(len(vins)))
            if input_index < len(vins):
                vin = vins[input_index]
                parts.append(str(vin.get("txid", "")))
                parts.append(str(vin.get("vout", 0)))
                parts.append(str(vin.get("sequence", 0xFFFFFFFF)))
            vouts = tx.get("vout", [])
            parts.append(str(len(vouts)))
            for vout in vouts:
                sat = int(round(float(vout.get("value", 0.0)) * 100_000_000))
                parts.append(str(sat))
                spk = vout.get("scriptPubKey", {})
                if isinstance(spk, dict):
                    parts.append(str(spk.get("hex", "")))
            parts.append(str(tx.get("locktime", 0)))
            parts.append("01000000")
            raw = "".join(parts).encode("utf-8")
            return utils.double_sha256(raw).hex()
        except Exception:
            return ""

    @staticmethod
    def is_p2pkh(script: bytes) -> bool:
        return (
            len(script) >= 25
            and script[0] == 0x76
            and script[1] == 0xA9
            and script[2] == 0x14
            and script[23] == 0x88
            and script[24] == 0xAC
        )

    @staticmethod
    def is_p2sh(script: bytes) -> bool:
        return (
            len(script) >= 23
            and script[0] == 0xA9
            and script[1] == 0x14
            and script[22] == 0x87
        )

    @staticmethod
    def is_multisig(script: bytes) -> bool:
        if len(script) < 3 or not (0x51 <= script[0] <= 0x60):
            return False
        pos = 1
        while pos < len(script) and script[pos] == 0x21:
            pos += 34
        if pos + 1 >= len(script):
            return False
        return (0x51 <= script[pos] <= 0x60) and script[pos + 1] == 0xAE

    @staticmethod
    def is_segwit(script: bytes) -> bool:
        return len(script) >= 3 and (0x00 <= script[0] <= 0x10) and (0x02 <= script[1] <= 0x28)

    @classmethod
    def extract_multisig_mn(cls, script: bytes) -> Tuple[int, int]:
        if not cls.is_multisig(script):
            return -1, -1
        m = script[0] - 0x50
        n = 0
        pos = 1
        while pos < len(script) and script[pos] == 0x21:
            n += 1
            pos += 34
        return m, n

    @staticmethod
    def check_r_value_reuse(r: str, other_r: str) -> bool:
        return bool(r) and r == other_r
