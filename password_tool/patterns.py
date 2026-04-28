"""
Pattern Detection Module
========================
Detects predictable patterns that dramatically reduce password strength:
  - Sequential characters  (ASCII progression, e.g. abc, 789, cba)
  - Repeated characters     (e.g. aaa, 111)
  - Keyboard-row patterns   (e.g. qwerty, asdfgh, ytrewq)
"""


# ---------------------------------------------------------------------------
# Keyboard patterns (common rows / diagonals + reverses)
# ---------------------------------------------------------------------------

_KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "qwert", "werty",
    "asdfgh", "asdf",
    "zxcvbn", "zxcv",
    "1234567890", "123456789", "12345678", "1234567",
    "123456", "12345", "1234",
    "09876", "98765", "5432",
    "qazwsx", "wsxedc",
]

_REVERSED_KEYBOARD_PATTERNS = [p[::-1] for p in _KEYBOARD_PATTERNS]
_ALL_KEYBOARD_PATTERNS = _KEYBOARD_PATTERNS + _REVERSED_KEYBOARD_PATTERNS


# ---------------------------------------------------------------------------
# Sequential detection (ASCII alphanumerics only)
# ---------------------------------------------------------------------------

_ASCII_LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ASCII_DIGIT = frozenset("0123456789")

def detect_sequential(password: str, min_run: int = 3) -> bool:
    """
    Return True if *password* contains *min_run* or more characters that
    form a consecutive ascending or descending sequence.

    Only considers ASCII alphanumerics to avoid false positives on Unicode.
    """
    if len(password) < min_run:
        return False

    filtered = [c for c in password
                if c in _ASCII_LOWER or c in _ASCII_UPPER or c in _ASCII_DIGIT]

    asc_run = 1
    desc_run = 1
    for i in range(1, len(filtered)):
        diff = ord(filtered[i]) - ord(filtered[i - 1])
        if diff == 1:
            asc_run += 1
            if asc_run >= min_run:
                return True
        else:
            asc_run = 1
        if diff == -1:
            desc_run += 1
            if desc_run >= min_run:
                return True
        else:
            desc_run = 1

    return False


# ---------------------------------------------------------------------------
# Repeated character detection
# ---------------------------------------------------------------------------

def detect_repeated(password: str, min_run: int = 3) -> bool:
    """
    Return True if *password* contains *min_run* or more identical
    consecutive characters (e.g. ``aaa``, ``111``).
    """
    if len(password) < min_run:
        return False

    run = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


# ---------------------------------------------------------------------------
# Keyboard-row pattern detection
# ---------------------------------------------------------------------------

def detect_keyboard_patterns(password: str) -> bool:
    """
    Return True if *password* contains a known keyboard-row substring.
    """
    pwd_lower = password.lower()
    for pattern in _ALL_KEYBOARD_PATTERNS:
        if pattern in pwd_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# Aggregate & penalty
# ---------------------------------------------------------------------------

def detect_all_patterns(password: str) -> dict:
    """
    Run all pattern detectors and return a summary dict::

        {"sequential": bool, "repeated": bool, "keyboard": bool}
    """
    return {
        "sequential": detect_sequential(password),
        "repeated":   detect_repeated(password),
        "keyboard":   detect_keyboard_patterns(password),
    }


PATTERN_PENALTY_PER_TYPE = -5


def pattern_penalty_from_result(patterns: dict) -> int:
    """
    Return a negative penalty (0 to -15) based on pre-computed pattern results.

    Use this when ``detect_all_patterns`` has already been called to avoid
    redundant detection.
    """
    penalty = 0
    if patterns["sequential"]:
        penalty += PATTERN_PENALTY_PER_TYPE
    if patterns["repeated"]:
        penalty += PATTERN_PENALTY_PER_TYPE
    if patterns["keyboard"]:
        penalty += PATTERN_PENALTY_PER_TYPE
    return penalty


def pattern_penalty(password: str) -> int:
    """
    Return a negative penalty (0 to -15) based on detected patterns.

    Runs detection internally. If you already have pattern results, use
    ``pattern_penalty_from_result`` instead.
    """
    return pattern_penalty_from_result(detect_all_patterns(password))
