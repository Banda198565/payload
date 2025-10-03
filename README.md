# Seven-layer Obfuscator

This repository contains a demonstrational seven-layer obfuscator backed by a
heuristic AI-like assistant.  The assistant analyses input text and derives a
configuration that controls each layer of the obfuscation pipeline.

## Features

- **Seven reversible layers** consisting of compression, XOR, Base64, padding,
  permutation, bit rotation and ASCII armouring.
- **Deterministic assistant** that inspects the message and proposes a plan
  (encryption keys, permutation, compression level, etc.).
- **Unicode aware** end-to-end workflow.

## Usage

```python
from src import LayerAdvisor, SevenLayerObfuscator

message = "Пример сообщения"
plan = LayerAdvisor().suggest_plan(message)
obfuscator = SevenLayerObfuscator(plan)
obfuscated = obfuscator.obfuscate(message)
original = obfuscator.deobfuscate(obfuscated)
assert original == message
```

Running the test-suite requires `pytest`:

```bash
pip install pytest
pytest
```
