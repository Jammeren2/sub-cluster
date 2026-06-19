#!/usr/bin/env python3
"""
secretbox.py — шифрование секретов «в покое» (at rest).

Секреты (пароль reg.ru и т.п.) настраиваются в веб-панели и хранятся в
синхронизируемой БД на всех узлах. Чтобы не держать их в открытом виде,
шифруем их симметрично ключом из переменной окружения SECRET_KEY.

Ключ Fernet выводится из SECRET_KEY через SHA-256 → urlsafe-base64, поэтому
SECRET_KEY может быть любой строкой (но одинаковой на всех узлах!).

Если библиотека cryptography недоступна или SECRET_KEY не задан — секрет
сохраняется с префиксом 'plain:' (без шифрования) и при старте печатается
предупреждение. Это позволяет запуститься в минимальной среде, но в проде
SECRET_KEY обязателен.
"""

import os
import base64
import hashlib

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - окружение без cryptography
    _HAVE_CRYPTO = False

    class InvalidToken(Exception):
        pass


def have_key():
    return bool(os.environ.get("SECRET_KEY"))


def crypto_ready():
    return _HAVE_CRYPTO and have_key()


def _fernet():
    raw = os.environ.get("SECRET_KEY", "")
    if not raw or not _HAVE_CRYPTO:
        return None
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext):
    """str → строка для хранения. Пусто остаётся пустым."""
    if not plaintext:
        return ""
    f = _fernet()
    if f is None:
        return "plain:" + plaintext
    return "enc:" + f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(stored):
    """Хранимая строка → исходный секрет. Непрочитанное → ''."""
    if not stored:
        return ""
    if stored.startswith("plain:"):
        return stored[len("plain:"):]
    if stored.startswith("enc:"):
        f = _fernet()
        if f is None:
            return ""
        try:
            return f.decrypt(stored[len("enc:"):].encode("ascii")).decode("utf-8")
        except (InvalidToken, Exception):
            return ""
    # Легаси/сырой текст без префикса.
    return stored


def is_encrypted(stored):
    return bool(stored) and stored.startswith("enc:")
