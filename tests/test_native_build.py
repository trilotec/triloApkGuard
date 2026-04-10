"""Tests for native lib source generation."""

from __future__ import annotations

import re

from trilo_dex import native_build


class _ReverseRandom:
    def shuffle(self, seq: list[int]) -> None:
        seq[:] = list(reversed(seq))


def test_generated_c_uses_explicit_string_lengths():
    source = native_build._generate_obfuscated_c(bytes(range(16)))

    assert "#include <stdio.h>" in source
    assert "#include <sys/syscall.h>" in source
    assert "static void _dec_str(char *out, const uint8_t *enc, size_t len, int key)" in source
    assert "out[len] = '\\0';" in source
    assert "_dec_str(path, _s03, sizeof(_s03), _str_key);" in source
    assert "_dec_str(tracer, _s04, sizeof(_s04), _str_key);" in source


def test_generated_c_reassembles_fragments_into_original_positions(monkeypatch):
    monkeypatch.setattr(native_build.secrets, "SystemRandom", lambda: _ReverseRandom())

    source = native_build._generate_obfuscated_c(bytes(range(16)))
    assignments = re.findall(r"key\[(\d+)\] = .*?_f(\d{2})", source)

    assert len(assignments) == 16
    assert {int(dst) for dst, _ in assignments} == set(range(16))
    assert {int(src) for _, src in assignments} == set(range(16))
    assert all(int(dst) == int(src) for dst, src in assignments)
