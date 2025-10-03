"""Seven-layer obfuscation pipeline.

The module provides :class:`SevenLayerObfuscator` which applies a stack of
reversible transformations to a text message.  The transformations operate on
bytes and are designed to be lossless so that a matching :meth:`deobfuscate`
call is guaranteed to recover the original payload.
"""
from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass
from typing import Sequence

from .assistant import ObfuscationPlan


class LayerProtocol:
    """Simple forward/backward protocol implemented by all layers."""

    def forward(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def backward(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class SevenLayerObfuscator:
    """Concrete seven-layer obfuscator.

    Parameters
    ----------
    plan:
        Configuration produced by :class:`~payload.assistant.LayerAdvisor`.
    """

    plan: ObfuscationPlan

    def __post_init__(self) -> None:
        self._layers: Sequence[LayerProtocol] = (
            _ZlibLayer(self.plan.compression_level),
            _XorLayer(self.plan.xor_key),
            _Base64Layer(self.plan.base64_variant),
            _PaddingLayer(self.plan.block_size),
            _PermutationLayer(self.plan.permutation),
            _BitRotationLayer(self.plan.bit_rotation),
            _AsciiArmorLayer(self.plan.armor),
        )

    def obfuscate(self, message: str) -> str:
        """Return an obfuscated representation of ``message``."""

        data = message.encode("utf-8")
        for layer in self._layers:
            data = layer.forward(data)
        return data.decode("ascii")

    def deobfuscate(self, payload: str) -> str:
        """Recover the original message from ``payload``."""

        data = payload.encode("ascii")
        for layer in reversed(self._layers):
            data = layer.backward(data)
        return data.decode("utf-8")


class _ZlibLayer(LayerProtocol):
    def __init__(self, level: int) -> None:
        self.level = max(0, min(9, level))

    def forward(self, data: bytes) -> bytes:
        return zlib.compress(data, self.level)

    def backward(self, data: bytes) -> bytes:
        return zlib.decompress(data)


class _XorLayer(LayerProtocol):
    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("key must not be empty")
        self.key = key

    def _apply(self, data: bytes) -> bytes:
        key = self.key
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

    forward = _apply
    backward = _apply


class _Base64Layer(LayerProtocol):
    def __init__(self, variant: str) -> None:
        if variant not in {"standard", "urlsafe"}:
            raise ValueError("variant must be 'standard' or 'urlsafe'")
        self.variant = variant

    def forward(self, data: bytes) -> bytes:
        if self.variant == "urlsafe":
            return base64.urlsafe_b64encode(data)
        return base64.b64encode(data)

    def backward(self, data: bytes) -> bytes:
        if self.variant == "urlsafe":
            return base64.urlsafe_b64decode(data)
        return base64.b64decode(data)


class _PaddingLayer(LayerProtocol):
    def __init__(self, block_size: int) -> None:
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        self.block_size = block_size

    def forward(self, data: bytes) -> bytes:
        pad_len = self.block_size - (len(data) % self.block_size)
        if pad_len == 0:
            pad_len = self.block_size
        return data + bytes([pad_len]) * pad_len

    def backward(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("cannot unpad empty data")
        pad_len = data[-1]
        if pad_len <= 0 or pad_len > self.block_size:
            raise ValueError("invalid padding")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("invalid padding")
        return data[:-pad_len]


class _PermutationLayer(LayerProtocol):
    def __init__(self, permutation: Sequence[int]) -> None:
        if not permutation:
            raise ValueError("permutation must not be empty")
        if sorted(permutation) != list(range(len(permutation))):
            raise ValueError("permutation must be a rearrangement of range(n)")
        self.permutation = tuple(permutation)
        inverse = [0] * len(permutation)
        for index, dest in enumerate(permutation):
            inverse[dest] = index
        self.inverse = tuple(inverse)

    def forward(self, data: bytes) -> bytes:
        block_size = len(self.permutation)
        if len(data) % block_size:
            raise ValueError("data length must be multiple of block size")
        return b"".join(
            self._permute_block(data[i : i + block_size])
            for i in range(0, len(data), block_size)
        )

    def backward(self, data: bytes) -> bytes:
        block_size = len(self.inverse)
        if len(data) % block_size:
            raise ValueError("data length must be multiple of block size")
        return b"".join(
            self._invert_block(data[i : i + block_size])
            for i in range(0, len(data), block_size)
        )

    def _permute_block(self, block: bytes) -> bytes:
        permuted = bytearray(len(block))
        for src_index, dest_index in enumerate(self.permutation):
            permuted[dest_index] = block[src_index]
        return bytes(permuted)

    def _invert_block(self, block: bytes) -> bytes:
        restored = bytearray(len(block))
        for dest_index, src_index in enumerate(self.inverse):
            restored[src_index] = block[dest_index]
        return bytes(restored)


class _BitRotationLayer(LayerProtocol):
    def __init__(self, shift: int) -> None:
        if not (1 <= shift <= 7):
            raise ValueError("shift must be in range 1..7")
        self.shift = shift

    def forward(self, data: bytes) -> bytes:
        shift = self.shift
        return bytes(((b << shift) & 0xFF) | (b >> (8 - shift)) for b in data)

    def backward(self, data: bytes) -> bytes:
        shift = self.shift
        return bytes((b >> shift) | ((b << (8 - shift)) & 0xFF) for b in data)


class _AsciiArmorLayer(LayerProtocol):
    def __init__(self, mode: str) -> None:
        if mode not in {"base32", "base85"}:
            raise ValueError("mode must be 'base32' or 'base85'")
        self.mode = mode

    def forward(self, data: bytes) -> bytes:
        if self.mode == "base32":
            return base64.b32encode(data)
        return base64.b85encode(data)

    def backward(self, data: bytes) -> bytes:
        if self.mode == "base32":
            return base64.b32decode(data)
        return base64.b85decode(data)


__all__ = ["SevenLayerObfuscator"]
