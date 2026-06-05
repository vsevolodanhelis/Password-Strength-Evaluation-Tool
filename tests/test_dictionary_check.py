"""Tests for the dictionary_check module."""
import pytest
from password_tool.dictionary_check import (
    is_common_password,
    contains_dictionary_word,
    levenshtein_distance,
    is_similar_to_common,
    COMMON_PASSWORDS,
)


# ---- Module-level ----

class TestCommonPasswordsList:
    def test_list_loaded(self):
        assert len(COMMON_PASSWORDS) > 0

    def test_list_has_181_entries(self):
        assert len(COMMON_PASSWORDS) == 181

    def test_entries_are_lowercase(self):
        for pwd in COMMON_PASSWORDS:
            assert pwd == pwd.lower()


# ---- is_common_password ----

class TestIsCommonPassword:
    def test_exact_match(self):
        assert is_common_password("password") is True

    def test_case_insensitive(self):
        assert is_common_password("PASSWORD") is True
        assert is_common_password("Password") is True

    def test_not_common(self):
        assert is_common_password("xK9!mZ2@qW5#") is False

    def test_similar_but_not_exact(self):
        # "xkcd" is not in the common passwords list
        assert is_common_password("xkcd") is False

    def test_empty(self):
        assert is_common_password("") is False


# ---- contains_dictionary_word ----

class TestContainsDictionaryWord:
    def test_exact_match_in_list(self):
        # "password" appears in "mypassword123"
        result = contains_dictionary_word("mypassword123")
        assert "password" in result

    def test_no_match(self):
        result = contains_dictionary_word("xK9mZ2qW5")
        assert len(result) == 0

    def test_limit(self):
        result = contains_dictionary_word("passwordpasswordpassword", limit=2)
        assert len(result) <= 2

    def test_short_words_excluded(self):
        # Words < 4 chars should not be returned
        result = contains_dictionary_word("123abc456")
        for word in result:
            assert len(word) >= 4

    def test_case_insensitive(self):
        result = contains_dictionary_word("MyPASSWORD123")
        assert len(result) > 0

    def test_multiple_matches(self):
        result = contains_dictionary_word("password1234admin")
        assert len(result) >= 2


# ---- levenshtein_distance ----

class TestLevenshteinDistance:
    def test_identical_strings(self):
        assert levenshtein_distance("hello", "hello") == 0

    def test_one_insertion(self):
        assert levenshtein_distance("hello", "helo") == 1

    def test_one_substitution(self):
        assert levenshtein_distance("hello", "hallo") == 1

    def test_completely_different(self):
        assert levenshtein_distance("abc", "xyz") == 3

    def test_empty_vs_string(self):
        assert levenshtein_distance("", "abc") == 3

    def test_both_empty(self):
        assert levenshtein_distance("", "") == 0

    def test_symmetric(self):
        assert levenshtein_distance("abc", "def") == levenshtein_distance("def", "abc")

    def test_single_char(self):
        assert levenshtein_distance("a", "b") == 1
        assert levenshtein_distance("a", "a") == 0


# ---- is_similar_to_common ----

class TestIsSimilarToCommon:
    def test_exact_match(self):
        result = is_similar_to_common("password")
        assert "password" in result

    def test_close_variant(self):
        # "passw0rd" is similar to "password" (Levenshtein distance 1)
        result = is_similar_to_common("passw0rd")
        assert len(result) > 0

    def test_long_password_skipped(self):
        # Passwords > 20 chars are skipped
        long_pwd = "a" * 25
        result = is_similar_to_common(long_pwd)
        assert result == []

    def test_not_similar(self):
        result = is_similar_to_common("xK9!mZ2@qW5#nB7")
        assert result == []

    def test_threshold(self):
        # With threshold=0, only exact matches (distance 0) are returned
        # "xkcd" is not a common password, so even with threshold=0 it shouldn't appear
        result = is_similar_to_common("xkcd", threshold=0)
        assert "xkcd" not in result

    def test_returns_list(self):
        result = is_similar_to_common("test")
        assert isinstance(result, list)
