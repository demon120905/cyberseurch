"""Модуль валидации пар подписей и фиксации уязвимостей повторного использования R-значения."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple

from core import utils
from core.signature_analyzer import Signature

ZERO_32 = "0" * 64


@dataclass
class RecoveryStats:
    attempts: int = 0
    successes: int = 0
    failures: int = 0

    @property
    def success_rate(self) -> float:
        return (self.successes / self.attempts) if self.attempts > 0 else 0.0


class KeyRecovery:
    """
    Проверяет пары ECDSA-подписей на уязвимость повторного использования nonce (R-value reuse)
    как между разными транзакциями, так и между разными входами одной транзакции,
    и формирует безопасный диагностический маркер уязвимости (без извлечения приватного ключа).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.attempts = 0
        self.successes = 0
        self.failures = 0

    @staticmethod
    def validate_signature_components(r: str, s: str, z: str) -> bool:
        if not (utils.is_hex_string(r) and utils.is_hex_string(s) and utils.is_hex_string(z)):
            return False
        if len(r) != 64 or len(s) != 64 or len(z) != 64:
            return False
        if r == ZERO_32 or s == ZERO_32:
            return False
        return True

    def validate_signature_pair(self, sig1: Signature, sig2: Signature) -> bool:
        if sig1.r != sig2.r:
            return False
        same_signer = (sig1.pubkey == sig2.pubkey) or (
            bool(sig1.address) and sig1.address == sig2.address and sig1.address not in ("UNKNOWN_BTC", "UNKNOWN_TRON")
        )
        if not same_signer:
            return False
        # Исключаем сравнение одного и того же входа одной и той же транзакции,
        # но РАЗРЕШАЕМ разные входы одной транзакции (частый кейс R-reuse в Bitcoin!).
        if sig1.txid == sig2.txid and sig1.input_index == sig2.input_index:
            return False
        # Разные сообщения подтверждаются либо z1 != z2, либо s1 != s2 (напр. при нестандартном SIGHASH)
        if sig1.z == sig2.z and sig1.s == sig2.s:
            return False
        if not self.validate_signature_components(sig1.r, sig1.s, sig1.z):
            return False
        if not self.validate_signature_components(sig2.r, sig2.s, sig2.z):
            return False
        return True

    def recover_private_key(self, sig1: Signature, sig2: Signature) -> Optional[str]:
        """
        Подтверждает уязвимость R-reuse для пары подписей и возвращает безопасный маркер обнаружения.
        (Сохраняет безопасное поведение оригинального сканера без извлечения приватного ключа.)
        """
        with self._lock:
            self.attempts += 1

        if not self.validate_signature_pair(sig1, sig2):
            with self._lock:
                self.failures += 1
            return None

        scope = "SAME_TX" if sig1.txid == sig2.txid else "CROSS_TX"
        marker = f"VULNERABILITY_DETECTED_{sig1.r[:8].upper()}_{scope}"
        with self._lock:
            self.successes += 1
        return marker

    def batch_recover_keys(
        self, signature_pairs: List[Tuple[Signature, Signature]]
    ) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        for sig1, sig2 in signature_pairs:
            marker = self.recover_private_key(sig1, sig2)
            if marker:
                results.append((marker, sig1.address))
        return results

    def get_stats(self) -> RecoveryStats:
        with self._lock:
            return RecoveryStats(
                attempts=self.attempts,
                successes=self.successes,
                failures=self.failures,
            )
