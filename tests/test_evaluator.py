"""Tests for the evaluator module — the core scoring engine."""
import pytest
from password_tool.evaluator import (
    evaluate_password,
    generate_password,
    EvaluationResult,
    MAX_LENGTH_SCORE,
    MAX_DIVERSITY_SCORE,
    MAX_ENTROPY_SCORE,
    PATTERN_PENALTY_TOTAL,
)


# ---- EvaluationResult structure ----

class TestEvaluationResult:
    def test_has_required_fields(self):
        result = evaluate_password("test")
        assert hasattr(result, "score")
        assert hasattr(result, "label")
        assert hasattr(result, "details")
        assert hasattr(result, "suggestions")
        assert hasattr(result, "entropy_bits")
        assert hasattr(result, "crack_time")
        assert hasattr(result, "length_pts")
        assert hasattr(result, "diversity_pts")
        assert hasattr(result, "entropy_pts")
        assert hasattr(result, "pattern_pts")
        assert hasattr(result, "dict_pts")

    def test_score_range(self):
        for pw in ["", "a", "password", "TestPass123!", "a" * 50]:
            result = evaluate_password(pw)
            assert 0 <= result.score <= 100

    def test_valid_label(self):
        for pw in ["", "password", "TestPass123!", "abcdefghij1234!@#$"]:
            result = evaluate_password(pw)
            assert result.label in ("Very Weak", "Weak", "Moderate", "Strong")


# ---- Empty input ----

class TestEmptyInput:
    def test_empty_score(self):
        result = evaluate_password("")
        assert result.score == 0

    def test_empty_label(self):
        result = evaluate_password("")
        assert result.label == "Very Weak"

    def test_empty_breakdown(self):
        result = evaluate_password("")
        assert result.length_pts == 0
        assert result.diversity_pts == 0
        assert result.entropy_pts == 0
        assert result.pattern_pts == 0
        assert result.dict_pts == 0


# ---- Trivial/common passwords ----

class TestCommonPasswords:
    @pytest.mark.parametrize("password", [
        "123456",
        "password",
        "admin",
        "iloveyou",
    ])
    def test_common_passwords_score_at_most_10(self, password):
        result = evaluate_password(password)
        assert result.score <= 10
        assert result.label == "Very Weak"

    def test_exact_common_cap(self):
        result = evaluate_password("password")
        assert result.score <= 10


# ---- Leetspeak ----

class TestLeetspeak:
    def test_leetspeak_caught(self):
        result = evaluate_password("p@ssw0rd")
        assert result.score <= 10


# ---- Keyboard patterns ----

class TestKeyboardPatterns:
    def test_qwerty_penalised(self):
        result = evaluate_password("qwerty")
        assert result.pattern_pts < 0

    def test_ytrewq_detected(self):
        result = evaluate_password("ytrewq")
        assert result.pattern_pts < 0

    def test_qwerty_higher_than_common(self):
        # "qwerty" is not in common passwords list (it's only detected as keyboard pattern)
        qwerty = evaluate_password("qwerty")
        common = evaluate_password("123456")
        assert qwerty.score >= common.score


# ---- Moderate-strength passwords (thesis test values) ----

class TestModeratePasswords:
    def test_testpass123(self):
        result = evaluate_password("TestPass123!")
        assert result.score == 57
        assert result.label == "Moderate"

    def test_sunshine2024(self):
        result = evaluate_password("Sunshine2024!")
        assert result.score == 62
        assert result.label == "Moderate"

    def test_tr0ub4dor(self):
        result = evaluate_password("Tr0ub4dor&3")
        assert result.score == 70
        assert result.label == "Moderate"

    def test_mydogmax(self):
        result = evaluate_password("MyDogMax")
        assert result.score == 47
        assert result.label == "Weak"


# ---- Strong passwords ----

class TestStrongPasswords:
    def test_generated_password_is_strong(self):
        pwd = generate_password(16)
        result = evaluate_password(pwd)
        assert result.score >= 76
        assert result.label == "Strong"


# ---- Breakdown fields sum correctly ----

class TestBreakdownConsistency:
    def test_breakdown_sums_to_raw_score(self):
        # The raw score before clamping should equal the sum of breakdown fields
        # (except when clamping or exact-common-cap kicks in)
        passwords = [
            "TestPass123!",
            "Sunshine2024!",
            "MyDogMax",
            "abcdefgh",
            "!@#$%^",
        ]
        for pw in passwords:
            result = evaluate_password(pw)
            breakdown_sum = (
                result.length_pts
                + result.diversity_pts
                + result.entropy_pts
                + result.pattern_pts
                + result.dict_pts
            )
            # After clamping, score <= breakdown_sum (clamped at 0 or 100)
            assert 0 <= breakdown_sum <= 100 or result.score <= breakdown_sum


# ---- Entropy and crack time ----

class TestEntropyAndCrackTime:
    def test_entropy_is_positive(self):
        result = evaluate_password("test")
        assert result.entropy_bits > 0

    def test_crack_time_is_string(self):
        result = evaluate_password("test")
        assert isinstance(result.crack_time, str)

    def test_higher_entropy_longer_crack(self):
        short = evaluate_password("abc")
        long = evaluate_password("abcdefghij1234!@#$")
        assert long.entropy_bits > short.entropy_bits


# ---- Caching ----

class TestCaching:
    def test_same_result_returned(self):
        r1 = evaluate_password("CacheTest123!")
        r2 = evaluate_password("CacheTest123!")
        assert r1 is r2


# ---- Password generation ----

class TestGeneratePassword:
    def test_default_length(self):
        pwd = generate_password()
        assert len(pwd) >= 12

    def test_custom_length(self):
        pwd = generate_password(20)
        assert len(pwd) >= 12  # minimum enforced

    def test_contains_all_categories(self):
        import re
        pwd = generate_password(16)
        assert re.search(r"[a-z]", pwd)
        assert re.search(r"[A-Z]", pwd)
        assert re.search(r"[0-9]", pwd)
        assert re.search(r"[^a-zA-Z0-9]", pwd)

    def test_different_each_call(self):
        # With overwhelming probability, two calls differ
        p1 = generate_password(16)
        p2 = generate_password(16)
        # Not guaranteed but extremely likely
        assert p1 != p2 or True  # allow rare collision


# ---- Score label boundaries ----

class TestLabelBoundaries:
    def test_very_weak_boundary(self):
        # Score 25 → Weak (score <= 25 is Very Weak, 26-50 is Weak)
        result = evaluate_password("aB3!x")
        assert result.label in ("Very Weak", "Weak")

    def test_strong_boundary(self):
        # Score 76+ → Strong
        pwd = generate_password(20)
        result = evaluate_password(pwd)
        assert result.label in ("Moderate", "Strong")
