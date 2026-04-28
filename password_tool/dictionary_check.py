"""
Dictionary Check Module
=======================
Checks whether a password matches or closely resembles entries in a
common-passwords list.

Features:
  - Exact match (case-insensitive)
  - Substring detection (dictionary words >= 4 chars)
  - Levenshtein distance similarity (only for passwords <= 20 chars)
"""

import os
import sys

# ---------------------------------------------------------------------------
# Load common passwords from file
# ---------------------------------------------------------------------------

_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")

def _load_common_passwords() -> list[str]:
    """Load the common-passwords list, one entry per line."""
    try:
        with open(_PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(
            f"Warning: '{_PASSWORDS_FILE}' not found. "
            f"Dictionary checking is disabled.",
            file=sys.stderr,
        )
        return []

COMMON_PASSWORDS: list[str] = _load_common_passwords()
_COMMON_PASSWORD_SET: set[str] = set(COMMON_PASSWORDS)


# ---------------------------------------------------------------------------
# Exact match
# ---------------------------------------------------------------------------

def is_common_password(password: str) -> bool:
    """Return True if *password* is an exact (case-insensitive) match."""
    return password.lower() in _COMMON_PASSWORD_SET


# ---------------------------------------------------------------------------
# Substring / dictionary-word detection
# ---------------------------------------------------------------------------

def contains_dictionary_word(password: str, limit: int = 0) -> list[str]:
    """
    Return a list of common passwords (>= 4 chars) that appear as a
    substring inside *password* (case-insensitive).

    If *limit* > 0, stop after finding that many matches.
    """
    pwd_lower = password.lower()
    found: list[str] = []
    for word in COMMON_PASSWORDS:
        if len(word) >= 4 and word in pwd_lower:
            found.append(word)
            if limit > 0 and len(found) >= limit:
                break
    return found


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions  = curr_row[j] + 1
            substitutions = prev_row[j] + (0 if c1 == c2 else 1)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ---------------------------------------------------------------------------
# Similarity check (guarded by length)
# ---------------------------------------------------------------------------

def is_similar_to_common(password: str, threshold: int = 2) -> list[str]:
    """
    Return common passwords whose Levenshtein distance to *password* is
    <= *threshold*.

    To avoid unnecessary computation, this check is **skipped** for
    passwords longer than 20 characters (returns an empty list).
    """
    if len(password) > 20:
        return []

    pwd_lower = password.lower()
    similar: list[str] = []
    for word in COMMON_PASSWORDS:
        if abs(len(word) - len(pwd_lower)) > threshold:
            continue
        if levenshtein_distance(pwd_lower, word) <= threshold:
            similar.append(word)
    return similar
