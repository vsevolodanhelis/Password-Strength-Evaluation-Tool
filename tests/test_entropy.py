"""Tests for the entropy module."""
import math
import pytest
from password_tool.entropy import (
    classify_characters,
    calculate_entropy,
    entropy_score,
    estimate_crack_time,
)


# ---- classify_characters ----

class TestClassifyCharacters:
    def test_lowercase_only(self):
        result = classify_characters("hello")
        assert result == {"lower": True, "upper": False, "digit": False, "special": False}

    def test_uppercase_only(self):
        result = classify_characters("HELLO")
        assert result == {"lower": False, "upper": True, "digit": False, "special": False}

    def test_digits_only(self):
        result = classify_characters("12345")
        assert result == {"lower": False, "upper": False, "digit": True, "special": False}

    def test_special_only(self):
        result = classify_characters("!@#$%")
        assert result == {"lower": False, "upper": False, "digit": False, "special": True}

    def test_all_categories(self):
        result = classify_characters("aB3!")
        assert result == {"lower": True, "upper": True, "digit": True, "special": True}

    def test_empty_string(self):
        result = classify_characters("")
        assert result == {"lower": False, "upper": False, "digit": False, "special": False}

    def test_mixed_lower_upper(self):
        result = classify_characters("aA")
        assert result == {"lower": True, "upper": True, "digit": False, "special": False}

    def test_leetspeak_detected(self):
        result = classify_characters("p@ssw0rd")
        assert result["lower"] is True
        assert result["digit"] is True
        assert result["special"] is True


# ---- calculate_entropy ----

class TestCalculateEntropy:
    def test_empty_string(self):
        assert calculate_entropy("") == 0.0

    def test_lowercase_only(self):
        # 8 chars, charset = 26
        expected = 8 * math.log2(26)
        assert calculate_entropy("abcdefgh") == pytest.approx(expected, abs=0.01)

    def test_all_categories(self):
        # charset = 26 + 26 + 10 + 32 = 94
        expected = 8 * math.log2(94)
        assert calculate_entropy("aB3!xY9#") == pytest.approx(expected, abs=0.01)

    def test_single_char(self):
        result = calculate_entropy("a")
        assert result == pytest.approx(1 * math.log2(26), abs=0.01)

    def test_longer_password_higher_entropy(self):
        short = calculate_entropy("abc")
        long = calculate_entropy("abcdefghij")
        assert long > short

    def test_more_categories_higher_entropy(self):
        lower_only = calculate_entropy("abcdefgh")
        mixed = calculate_entropy("aB3!xY9#")
        assert mixed > lower_only


# ---- entropy_score ----

class TestEntropyScore:
    def test_very_low_entropy(self):
        # < 28 bits → 5
        assert entropy_score("abc") == 5

    def test_low_entropy(self):
        # 28-35 bits → 10
        # 6 lowercase chars: 6 * log2(26) ≈ 28.2
        assert entropy_score("abcdef") == 10

    def test_medium_entropy(self):
        # 36-59 bits → 20
        # 8 chars with 2 categories: 8 * log2(52) ≈ 45.6
        assert entropy_score("abcABC12") == 20

    def test_high_entropy(self):
        # ≥ 60 bits → 30
        # 12 chars with all 4 categories: 12 * log2(94) ≈ 78.7
        assert entropy_score("TestPass123!") == 30

    def test_boundary_28(self):
        # Exactly 28 bits should give 10
        # charset 26, length 5: 5 * log2(26) ≈ 23.5 — not enough
        # charset 94, length 5: 5 * log2(94) ≈ 32.6 — should give 10
        score = entropy_score("aB3!x")
        assert score == 10

    def test_boundary_60(self):
        # charset 94, length 9: 9 * log2(94) ≈ 58.7 — should give 20
        # charset 94, length 10: 10 * log2(94) ≈ 65.2 — should give 30
        assert entropy_score("aB3!xY9#q") == 20
        assert entropy_score("aB3!xY9#qW") == 30


# ---- estimate_crack_time ----

class TestEstimateCrackTime:
    def test_zero_entropy(self):
        assert estimate_crack_time(0) == "instant"

    def test_negative_entropy(self):
        assert estimate_crack_time(-5) == "instant"

    def test_very_high_entropy(self):
        # > 200 bits → centuries+
        assert estimate_crack_time(250) == "centuries+"

    def test_low_entropy(self):
        # ~30 bits → should be fast
        result = estimate_crack_time(30)
        assert "seconds" in result or "less than" in result

    def test_medium_entropy(self):
        # ~60 bits → should be in years range
        result = estimate_crack_time(60)
        assert "years" in result or "centuries" in result

    def test_returns_string(self):
        result = estimate_crack_time(50)
        assert isinstance(result, str)

    def test_known_value_approx(self):
        # 37.6 bits → 2^37.6 / 10^10 ≈ 100 billion / 10 billion ≈ 10 seconds
        result = estimate_crack_time(37.6)
        assert "seconds" in result
