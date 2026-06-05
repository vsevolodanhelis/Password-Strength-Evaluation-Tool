"""Tests for the patterns module."""
import pytest
from password_tool.patterns import (
    detect_sequential,
    detect_repeated,
    detect_keyboard_patterns,
    detect_all_patterns,
    pattern_penalty_from_result,
    pattern_penalty,
)


# ---- detect_sequential ----

class TestDetectSequential:
    def test_ascending(self):
        assert detect_sequential("abc") is True

    def test_descending(self):
        assert detect_sequential("cba") is True

    def test_digit_sequence(self):
        assert detect_sequential("123") is True

    def test_long_sequence(self):
        assert detect_sequential("abcdefgh") is True

    def test_no_sequence(self):
        assert detect_sequential("aceg") is False

    def test_too_short(self):
        assert detect_sequential("ab") is False

    def test_empty(self):
        assert detect_sequential("") is False

    def test_non_contiguous(self):
        assert detect_sequential("ace") is False

    def test_sequence_in_middle(self):
        assert detect_sequential("xabcz") is True

    def test_min_run_4(self):
        assert detect_sequential("abcd", min_run=4) is True
        assert detect_sequential("abc", min_run=4) is False


# ---- detect_repeated ----

class TestDetectRepeated:
    def test_triple(self):
        assert detect_repeated("aaa") is True

    def test_quad(self):
        assert detect_repeated("1111") is True

    def test_no_repeat(self):
        assert detect_repeated("abc") is False

    def test_double_only(self):
        assert detect_repeated("aa") is False

    def test_empty(self):
        assert detect_repeated("") is False

    def test_repeat_in_middle(self):
        assert detect_repeated("abbbcd") is True

    def test_different_chars(self):
        assert detect_repeated("abcabc") is False

    def test_min_run_4(self):
        assert detect_repeated("aaa", min_run=4) is False
        assert detect_repeated("aaaa", min_run=4) is True


# ---- detect_keyboard_patterns ----

class TestDetectKeyboardPatterns:
    def test_qwerty(self):
        assert detect_keyboard_patterns("qwerty") is True

    def test_asdfgh(self):
        assert detect_keyboard_patterns("asdfgh") is True

    def test_zxcvbn(self):
        assert detect_keyboard_patterns("zxcvbn") is True

    def test_reversed_qwerty(self):
        assert detect_keyboard_patterns("ytrewq") is True

    def test_reversed_asdfgh(self):
        assert detect_keyboard_patterns("hgfdsa") is True

    def test_uppercase_qwerty(self):
        assert detect_keyboard_patterns("QWERTY") is True

    def test_qwerty_in_password(self):
        assert detect_keyboard_patterns("myPasswordqwerty123") is True

    def test_no_pattern(self):
        assert detect_keyboard_patterns("randomxyz") is False

    def test_empty(self):
        assert detect_keyboard_patterns("") is False

    def test_numeric_sequence(self):
        assert detect_keyboard_patterns("123456") is True

    def test_partial_pattern(self):
        # "qwerty" is detected inside a longer password
        assert detect_keyboard_patterns("abc123qwertyxyz") is True
        # "qwe" alone doesn't match any full pattern
        assert detect_keyboard_patterns("qwe") is False

    def test_diagonal_pattern(self):
        assert detect_keyboard_patterns("qazwsx") is True


# ---- detect_all_patterns ----

class TestDetectAllPatterns:
    def test_no_patterns(self):
        result = detect_all_patterns("random")
        assert result == {"sequential": False, "repeated": False, "keyboard": False}

    def test_all_patterns(self):
        # Sequential + keyboard: "qwerty" has no sequence, but "123" is sequential
        result = detect_all_patterns("qwerty123")
        assert result["sequential"] is True
        assert result["keyboard"] is True

    def test_keyboard_only(self):
        result = detect_all_patterns("qwerty")
        # qwerty: all unique chars (no repeat), not sequential (not ascii consecutive), but is keyboard
        assert result == {"sequential": False, "repeated": False, "keyboard": True}

    def test_returns_dict(self):
        result = detect_all_patterns("test")
        assert isinstance(result, dict)
        assert set(result.keys()) == {"sequential", "repeated", "keyboard"}


# ---- pattern_penalty ----

class TestPatternPenalty:
    def test_no_patterns(self):
        assert pattern_penalty("random") == 0

    def test_single_penalty(self):
        # "123" is sequential only
        assert pattern_penalty("123") == -5

    def test_keyboard_penalty(self):
        assert pattern_penalty("qwerty") == -5  # keyboard only (no repeat, no sequential)

    def test_max_penalty(self):
        # Password with all three pattern types
        # "aaa123qwerty" — repeated (aaa), sequential (123), keyboard (qwerty)
        result = pattern_penalty("aaa123qwerty")
        assert result == -15

    def test_pattern_penalty_from_result(self):
        patterns = {"sequential": True, "repeated": False, "keyboard": True}
        assert pattern_penalty_from_result(patterns) == -10

    def test_penalty_from_no_patterns(self):
        patterns = {"sequential": False, "repeated": False, "keyboard": False}
        assert pattern_penalty_from_result(patterns) == 0
