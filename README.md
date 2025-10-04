# Obfuscator Utility

This repository provides a small XOR-based obfuscation helper. The
script uses the bundled `key.bin` and `iv.bin` files to scramble and
descramble arbitrary byte sequences. Because the transformation is
symmetrical, running the tool twice returns the original data.

## Usage

```bash
python obfuscator.py encode <input> <output>
python obfuscator.py decode <input> <output>
```

Passing `-` as the input or output path switches to standard input or
standard output respectively.
