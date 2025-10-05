"""Simple XOR-based obfuscation utility.

Reads key and IV from binary files located alongside the script
(`key.bin` and `iv.bin`) and applies a reversible XOR obfuscation to
arbitrary byte sequences.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent
KEY_PATH = REPO_ROOT / "key.bin"
IV_PATH = REPO_ROOT / "iv.bin"


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:  # pragma: no cover - defensive branch
        raise SystemExit(f"Required file not found: {path}") from exc


def _xor_stream(data: bytes, key: bytes, iv: bytes) -> bytes:
    if not key or not iv:
        raise ValueError("Key and IV must not be empty")

    key_len = len(key)
    iv_len = len(iv)
    result = bytearray(len(data))

    for index, byte in enumerate(data):
        result[index] = byte ^ key[index % key_len] ^ iv[index % iv_len]

    return bytes(result)


def obfuscate(data: bytes, *, key: bytes | None = None, iv: bytes | None = None) -> bytes:
    """Obfuscate *data* using the bundled key and IV.

    The transformation is symmetrical – calling :func:`obfuscate` on the
    output will return the original input.
    """

    key_bytes = key if key is not None else _read_bytes(KEY_PATH)
    iv_bytes = iv if iv is not None else _read_bytes(IV_PATH)
    return _xor_stream(data, key_bytes, iv_bytes)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="XOR-based obfuscation utility")
    parser.add_argument("mode", choices={"encode", "decode"}, help="Operation to perform")
    parser.add_argument("input", help="Input file path or '-' to read from stdin")
    parser.add_argument("output", help="Output file path or '-' to write to stdout")

    args = parser.parse_args(argv)

    data: bytes
    if args.input == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.input).read_bytes()

    result = obfuscate(data)

    if args.output == "-":
        sys.stdout.buffer.write(result)
    else:
        Path(args.output).write_bytes(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
