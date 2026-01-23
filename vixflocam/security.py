from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CryptProtectData = _crypt32.CryptProtectData
_CryptProtectData.argtypes = [
    ctypes.POINTER(_DataBlob),
    wintypes.LPCWSTR,
    ctypes.POINTER(_DataBlob),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DataBlob),
]
_CryptProtectData.restype = wintypes.BOOL

_CryptUnprotectData = _crypt32.CryptUnprotectData
_CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DataBlob),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(_DataBlob),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DataBlob),
]
_CryptUnprotectData.restype = wintypes.BOOL

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [ctypes.c_void_p]
_LocalFree.restype = ctypes.c_void_p


DPAPI_UI_FORBIDDEN = 0x1


@dataclass(frozen=True)
class SecretString:
    """Wrapper minimal ca să evităm print accidental."""

    value: str

    def __repr__(self) -> str:  # pragma: no cover
        return "<secret>"


def _blob_from_bytes(data: bytes) -> _DataBlob:
    buf = ctypes.create_string_buffer(data)
    return _DataBlob(cbData=len(data), pbData=ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def _bytes_from_blob(blob: _DataBlob) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def dpapi_encrypt_to_b64(plaintext: str) -> str:
    """Criptează cu Windows DPAPI pentru user-ul curent; returnează base64."""
    data_in = _blob_from_bytes(plaintext.encode("utf-8"))
    data_out = _DataBlob()

    ok = _CryptProtectData(
        ctypes.byref(data_in),
        None,
        None,
        None,
        None,
        DPAPI_UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise OSError(ctypes.get_last_error())

    try:
        encrypted = _bytes_from_blob(data_out)
        return base64.b64encode(encrypted).decode("ascii")
    finally:
        if data_out.pbData:
            _LocalFree(data_out.pbData)


def dpapi_decrypt_from_b64(ciphertext_b64: str) -> SecretString:
    """Decriptează base64 DPAPI; returnează SecretString."""
    encrypted = base64.b64decode(ciphertext_b64.encode("ascii"))
    data_in = _blob_from_bytes(encrypted)
    data_out = _DataBlob()

    ok = _CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        None,
        None,
        None,
        DPAPI_UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise OSError(ctypes.get_last_error())

    try:
        plaintext = _bytes_from_blob(data_out).decode("utf-8", errors="strict")
        return SecretString(plaintext)
    finally:
        if data_out.pbData:
            _LocalFree(data_out.pbData)
