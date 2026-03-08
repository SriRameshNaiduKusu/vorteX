"""Tests for vortex/payloads/__init__.py and payload files."""

import os
import pytest
from vortex.payloads import load_payloads, _PAYLOADS_DIR


PAYLOAD_FILES = ["xss.txt", "sqli.txt", "ssrf.txt", "lfi.txt"]


@pytest.mark.parametrize("filename", PAYLOAD_FILES)
def test_payload_file_exists(filename):
    path = os.path.join(_PAYLOADS_DIR, filename)
    assert os.path.isfile(path), f"Payload file not found: {path}"


@pytest.mark.parametrize("filename", PAYLOAD_FILES)
def test_payload_file_non_empty(filename):
    payloads = load_payloads(filename)
    assert len(payloads) > 0, f"Payload file is empty: {filename}"


@pytest.mark.parametrize("filename", PAYLOAD_FILES)
def test_payload_file_has_minimum_entries(filename):
    """Each payload file should have at least 20 entries."""
    payloads = load_payloads(filename)
    assert len(payloads) >= 20, (
        f"{filename} has only {len(payloads)} payloads; expected at least 20"
    )


def test_load_payloads_strips_whitespace():
    """Ensure loaded payloads are stripped of surrounding whitespace."""
    payloads = load_payloads("xss.txt")
    for p in payloads:
        assert p == p.strip(), f"Payload not stripped: {p!r}"


def test_load_payloads_no_empty_strings():
    """Ensure no empty strings appear in the loaded list."""
    for filename in PAYLOAD_FILES:
        payloads = load_payloads(filename)
        assert "" not in payloads, f"Empty string found in {filename}"
