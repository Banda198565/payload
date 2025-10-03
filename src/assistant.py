"""Heuristic "AI" assistant for configuring the seven-layer obfuscator.

The goal of the assistant is to analyse the user provided payload and derive
configuration parameters that feed the obfuscation pipeline.  While this is not
an actual machine learning model, the assistant mimics an intelligent helper by
combining statistical analysis with deterministic pseudo-random number
generation.  This keeps the suggestions reproducible while still reacting to the
shape of the source text.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from statistics import mean
from typing import List, Sequence


@dataclass(frozen=True)
class ObfuscationPlan:
    """Container for the seven-layer obfuscator configuration.

    Attributes
    ----------
    xor_key:
        The byte-string used by the XOR layer.  The key length influences the
        diffusion and the plan ensures a minimum length of 8 bytes.
    block_size:
        Block size for the permutation and padding layers.  The permutation is
        defined over ``range(block_size)`` and both layers must agree on the same
        value.
    permutation:
        Concrete permutation used by :class:`PermutationLayer`.  The list length
        matches ``block_size`` and contains every integer in ``range(block_size)``
        exactly once.
    bit_rotation:
        How many bits (1-7) each byte is rotated to the left within the bit
        rotation layer.  The inverse operation rotates in the other direction.
    compression_level:
        Zlib compression level (0-9).  The assistant tweaks this depending on
        the entropy of the source text.
    base64_variant:
        Either ``"standard"`` or ``"urlsafe"``.  ``urlsafe`` avoids ``+`` and
        ``/`` which might be handy when embedding the payload in URLs.
    armor:
        Final ASCII armoring step.  ``"base32"`` is compact yet conservative for
        short inputs, whereas ``"base85"`` is denser and preferred for longer
        texts.
    """

    xor_key: bytes
    block_size: int
    permutation: Sequence[int]
    bit_rotation: int
    compression_level: int
    base64_variant: str
    armor: str

    def describe(self) -> str:
        """Return a human-readable description of the plan."""

        permutation_preview = "-".join(str(i) for i in self.permutation[:6])
        return (
            "Obfuscation plan: "
            f"xor_key={len(self.xor_key)} bytes, "
            f"block_size={self.block_size}, "
            f"perm~[{permutation_preview}...], "
            f"bit_rotation={self.bit_rotation}, "
            f"compression_level={self.compression_level}, "
            f"base64_variant={self.base64_variant}, "
            f"armor={self.armor}"
        )


class LayerAdvisor:
    """Pseudo-AI assistant that crafts an :class:`ObfuscationPlan`.

    The adviser uses deterministic randomness that depends on statistics of the
    message.  That way repeated calls with the same message return the same
    configuration, yet small changes in the input yield noticeably different
    results.
    """

    def __init__(self, *, seed: int | None = None) -> None:
        self._seed = seed

    def suggest_plan(self, message: str) -> ObfuscationPlan:
        """Analyse ``message`` and return a tailored obfuscation plan."""

        if not message:
            raise ValueError("message must not be empty")

        # Basic features about the payload.
        code_points = [ord(ch) for ch in message]
        length = len(code_points)
        ascii_share = sum(1 for cp in code_points if cp < 128) / length
        diversity = len(set(code_points)) / length
        avg_code_point = mean(code_points)

        # Deterministic random seed derived from message statistics.
        digest = sha256(message.encode("utf-8")).digest()
        seed = int.from_bytes(digest[:8], "big")
        if self._seed is not None:
            seed ^= self._seed

        rng = _DeterministicRandom(seed)

        # XOR key length scales with message length and diversity.
        base_key_len = max(8, min(48, int(length * (0.25 + diversity))))
        xor_key = bytes(rng.randint(0, 255) for _ in range(base_key_len))

        # Block size influences permutation and padding.
        block_size_candidates = [6, 7, 8, 9, 10, 12]
        block_size = block_size_candidates[int(avg_code_point) % len(block_size_candidates)]

        permutation = list(range(block_size))
        rng.shuffle(permutation)

        # Bit rotation between 1 and 7.  Higher entropy texts rotate further.
        rotation = max(1, min(7, int(1 + diversity * 7)))

        # Compression level derived from ascii share and length.
        if length < 32:
            compression_level = 6
        elif ascii_share < 0.6:
            compression_level = 9
        else:
            compression_level = 4 + int((1 - diversity) * 3)
        compression_level = max(1, min(9, compression_level))

        base64_variant = "urlsafe" if ascii_share > 0.85 else "standard"
        armor = "base85" if length > 48 else "base32"

        return ObfuscationPlan(
            xor_key=xor_key,
            block_size=block_size,
            permutation=tuple(permutation),
            bit_rotation=rotation,
            compression_level=compression_level,
            base64_variant=base64_variant,
            armor=armor,
        )


class _DeterministicRandom:
    """Minimal random generator with shuffle support.

    We keep the implementation small to avoid depending on :mod:`random` which
    carries global state.  The generator implements only the functionality we
    require (integers and shuffling).
    """

    def __init__(self, seed: int) -> None:
        self.state = seed & ((1 << 64) - 1)
        if self.state == 0:
            self.state = 0xDEADBEEFCAFEBABE

    def randint(self, a: int, b: int) -> int:
        if a > b:
            raise ValueError("a must be <= b")
        span = b - a + 1
        self.state = (1103515245 * self.state + 12345) & 0x7FFFFFFF
        return a + self.state % span

    def shuffle(self, items: List[int]) -> None:
        for i in range(len(items) - 1, 0, -1):
            j = self.randint(0, i)
            items[i], items[j] = items[j], items[i]


__all__ = ["LayerAdvisor", "ObfuscationPlan"]
