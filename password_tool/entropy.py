"""
Entropy Calculation Module
==========================
Estimates password entropy using information theory:
    H = L × log₂(N)
where L = password length, N = character set size (dynamic).

Also provides a brute-force crack-time estimate.
"""

import math
import re


# ---------------------------------------------------------------------------
# Pre-compiled character-category regexes
# ---------------------------------------------------------------------------

_RE_LOWER = re.compile(r"[a-z]")
_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"[0-9]")
_RE_SPECIAL = re.compile(r"[^a-zA-Z0-9]")

_CATEGORY_NAMES = {
    "lower": "lowercase letters",
    "upper": "uppercase letters",
    "digit": "digits",
    "special": "special characters",
}


def classify_characters(password: str) -> dict[str, bool]:
    """
    Return a dict indicating which character categories appear in *password*.

        {"lower": bool, "upper": bool, "digit": bool, "special": bool}
    """
    return {
        "lower":   bool(_RE_LOWER.search(password)),
        "upper":   bool(_RE_UPPER.search(password)),
        "digit":   bool(_RE_DIGIT.search(password)),
        "special": bool(_RE_SPECIAL.search(password)),
    }


# ---------------------------------------------------------------------------
# Character-set size helpers
# ---------------------------------------------------------------------------

def _charset_size(password: str) -> int:
    """
    Calculate the effective character-set size based on which character
    categories actually appear in the password.

    - lowercase letters  -> +26
    - uppercase letters  -> +26
    - digits             -> +10
    - symbols / special  -> +32
    """
    cats = classify_characters(password)
    size = 0
    if cats["lower"]:
        size += 26
    if cats["upper"]:
        size += 26
    if cats["digit"]:
        size += 10
    if cats["special"]:
        size += 32
    return size if size > 0 else 1


# ---------------------------------------------------------------------------
# Core entropy calculation
# ---------------------------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """
    Return estimated entropy in bits.

    H = L × log₂(N)
    """
    length = len(password)
    charset = _charset_size(password)
    if length == 0:
        return 0.0
    return length * math.log2(charset)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def entropy_score(password: str) -> int:
    """
    Map entropy bits to a 0-30 point score.

    < 28 bits  →  5
    28-35 bits → 10
    36-59 bits → 20
    ≥ 60 bits  → 30
    """
    bits = calculate_entropy(password)
    if bits >= 60:
        return 30
    elif bits >= 36:
        return 20
    elif bits >= 28:
        return 10
    else:
        return 5


# ---------------------------------------------------------------------------
# Time-to-crack estimate
# ---------------------------------------------------------------------------

_GUESSES_PER_SECOND = 10_000_000_000        # 10 billion (modern GPU)

_SECONDS_PER_MINUTE = 60
_SECONDS_PER_HOUR  = 3_600
_SECONDS_PER_DAY   = 86_400
_SECONDS_PER_YEAR  = 31_536_000

def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimate brute-force crack time assuming *_GUESSES_PER_SECOND* guesses
    per second, and return a human-readable string.
    """
    if entropy_bits <= 0:
        return "instant"

    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / _GUESSES_PER_SECOND

    if seconds < 1:
        return "less than a second"
    if seconds < _SECONDS_PER_MINUTE:
        return f"{int(seconds)} seconds"
    if seconds < _SECONDS_PER_HOUR:
        return f"{int(seconds // _SECONDS_PER_MINUTE)} minutes"
    if seconds < _SECONDS_PER_DAY:
        return f"{int(seconds // _SECONDS_PER_HOUR)} hours"
    if seconds < _SECONDS_PER_YEAR:
        return f"{int(seconds // _SECONDS_PER_DAY)} days"
    if seconds < _SECONDS_PER_YEAR * 1_000:
        return f"{int(seconds // _SECONDS_PER_YEAR)} years"
    if seconds < _SECONDS_PER_YEAR * 1_000_000:
        return f"{int(seconds // (_SECONDS_PER_YEAR * 1_000))} thousand years"
    if seconds < _SECONDS_PER_YEAR * 1_000_000_000:
        return f"{int(seconds // (_SECONDS_PER_YEAR * 1_000_000))} million years"
    if seconds < _SECONDS_PER_YEAR * 1_000_000_000_000:
        return f"{int(seconds // (_SECONDS_PER_YEAR * 1_000_000_000))} billion years"
    return "centuries+"
