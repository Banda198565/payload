import pytest

from src import LayerAdvisor, SevenLayerObfuscator


def round_trip(message: str) -> str:
    advisor = LayerAdvisor(seed=1234)
    plan = advisor.suggest_plan(message)
    obfuscator = SevenLayerObfuscator(plan)
    encrypted = obfuscator.obfuscate(message)
    assert encrypted != message
    return obfuscator.deobfuscate(encrypted)


def test_round_trip_ascii():
    message = "Hello, layered obfuscation!"
    assert round_trip(message) == message


def test_round_trip_unicode():
    message = "Привет, мир — 😀"
    assert round_trip(message) == message


def test_different_messages_produce_different_payloads():
    advisor = LayerAdvisor(seed=42)
    plan_a = advisor.suggest_plan("first message")
    plan_b = advisor.suggest_plan("second message")
    obfuscator_a = SevenLayerObfuscator(plan_a)
    obfuscator_b = SevenLayerObfuscator(plan_b)
    assert obfuscator_a.obfuscate("first message") != obfuscator_b.obfuscate("second message")


def test_invalid_deobfuscation_raises():
    advisor = LayerAdvisor(seed=1)
    plan = advisor.suggest_plan("validate")
    obfuscator = SevenLayerObfuscator(plan)
    payload = obfuscator.obfuscate("validate")
    # Corrupt the payload by dropping the last character.
    with pytest.raises(ValueError):
        obfuscator.deobfuscate(payload[:-1])
