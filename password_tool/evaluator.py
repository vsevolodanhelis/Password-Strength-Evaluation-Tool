"""
Password Evaluator Module
=========================
The central scoring engine.  Combines five analysis dimensions:

1. Rule-based length scoring           (0 - MAX_LENGTH_SCORE pts)
2. Character-diversity scoring         (0 - MAX_DIVERSITY_SCORE pts)
3. Entropy-based scoring               (0 - MAX_ENTROPY_SCORE pts)
4. Pattern penalty                     (0 to PATTERN_PENALTY_TOTAL pts)
5. Dictionary penalty                  (cap / SIMILAR_PENALTY pts)

Final score is clamped to 0-100.
"""

import functools
import secrets
import string
from dataclasses import dataclass, field

from password_tool.entropy import (
    calculate_entropy,
    classify_characters,
    entropy_score,
    estimate_crack_time,
    _CATEGORY_NAMES,
)
from password_tool.dictionary_check import (
    is_common_password,
    contains_dictionary_word,
    is_similar_to_common,
)
from password_tool.patterns import pattern_penalty_from_result, detect_all_patterns


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvaluationResult:
    score:        int
    label:        str
    details:      list[str] = field(default_factory=list)
    suggestions:  list[str] = field(default_factory=list)
    entropy_bits: float     = 0.0
    crack_time:   str       = "instant"


# ---------------------------------------------------------------------------
# Scoring constants (named for clarity and tunability)
# ---------------------------------------------------------------------------

MAX_LENGTH_SCORE    = 25
MAX_DIVERSITY_SCORE = 25
MAX_ENTROPY_SCORE   = 30

POINTS_PER_CATEGORY     = 6
ALL_CATEGORIES_BONUS    = 1

PATTERN_PENALTY_PER_TYPE = -5
PATTERN_PENALTY_TOTAL    = -15

SIMILAR_PENALTY      = -20
DICT_WORD_PENALTY    = -15
EXACT_COMMON_CAP     = 10


# ---------------------------------------------------------------------------
# Individual scoring helpers
# ---------------------------------------------------------------------------

def _length_score(password: str) -> int:
    """Score based on password length (0 - MAX_LENGTH_SCORE)."""
    length = len(password)
    if length >= 16:
        return 25
    elif length >= 12:
        return 22
    elif length >= 8:
        return 15
    elif length >= 6:
        return 5
    else:
        return 0


def _diversity_score(password: str) -> tuple[int, list[str], list[str]]:
    """
    Score based on character-category diversity (0 - MAX_DIVERSITY_SCORE).

    Returns (score, present_categories, missing_categories).
    """
    cats = classify_characters(password)

    present: list[str] = []
    missing: list[str] = []
    for key, found in cats.items():
        name = _CATEGORY_NAMES[key]
        if found:
            present.append(name)
        else:
            missing.append(name)

    count = len(present)
    score = count * POINTS_PER_CATEGORY
    if count == 4:
        score += ALL_CATEGORIES_BONUS
    return min(score, MAX_DIVERSITY_SCORE), present, missing


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

_EVAL_CACHE: dict[str, EvaluationResult] = {}

def evaluate_password(password: str) -> EvaluationResult:
    """
    Evaluate *password* and return an EvaluationResult.
    """
    if not password:
        return EvaluationResult(
            score=0,
            label="Very Weak",
            details=["No password entered"],
            suggestions=["Enter a password to evaluate."],
        )

    cached = _EVAL_CACHE.get(password)
    if cached is not None:
        return cached

    details:     list[str] = []
    suggestions: list[str] = []

    # --- 1. Length (0 - MAX_LENGTH_SCORE) -----------------------------------
    l_score = _length_score(password)
    if len(password) >= 12:
        details.append("\u2713 Good length (12+ characters)")
    elif len(password) >= 8:
        details.append("\u2713 Acceptable length (8-11 characters)")
        suggestions.append(
            "Use 12 or more characters \u2014 longer passwords are "
            "exponentially harder to crack."
        )
    else:
        details.append("\u2717 Too short (under 8 characters)")
        suggestions.append(
            "Use at least 12 characters. Short passwords can be "
            "brute-forced in seconds."
        )

    # --- 2. Character diversity (0 - MAX_DIVERSITY_SCORE) ------------------
    d_score, present, missing = _diversity_score(password)
    for cat in present:
        details.append(f"\u2713 Contains {cat}")
    for cat in missing:
        details.append(f"\u2717 Missing {cat}")
        if cat == "lowercase letters":
            suggestions.append("Add lowercase letters (a-z) to increase character diversity.")
        elif cat == "uppercase letters":
            suggestions.append("Add uppercase letters (A-Z) to strengthen your password's entropy.")
        elif cat == "digits":
            suggestions.append("Include numbers (0-9) to strengthen entropy and resist attacks.")
        elif cat == "special characters":
            suggestions.append("Add special characters like  !  @  #  $  %  to increase unpredictability.")
        else:
            suggestions.append(f"Add {cat} to increase diversity.")

    # --- 3. Entropy (0 - MAX_ENTROPY_SCORE) --------------------------------
    e_bits  = calculate_entropy(password)
    e_score = entropy_score(password)
    crack   = estimate_crack_time(e_bits)
    details.append(f"  Entropy: {e_bits:.1f} bits")

    # --- 4. Pattern penalty (0 to PATTERN_PENALTY_TOTAL) --------------------
    patterns  = detect_all_patterns(password)
    p_penalty = pattern_penalty_from_result(patterns)
    if patterns["sequential"]:
        details.append("\u2717 Contains sequential characters (e.g. abc, 123)")
        suggestions.append("Avoid sequential characters (abc, 123) \u2014 they are trivially guessable.")
    if patterns["repeated"]:
        details.append("\u2717 Contains repeated characters (e.g. aaa, 111)")
        suggestions.append("Avoid repeating the same character (aaa, 111) \u2014 patterns weaken passwords.")
    if patterns["keyboard"]:
        details.append("\u2717 Contains keyboard pattern (e.g. qwerty, asdf)")
        suggestions.append("Avoid keyboard patterns like qwerty or asdf \u2014 these are in every cracking dictionary.")

    # --- 5. Dictionary penalty ----------------------------------------------
    dict_penalty  = 0
    is_exact      = is_common_password(password)
    dict_words    = contains_dictionary_word(password)
    similar_words = is_similar_to_common(password)

    if is_exact:
        details.append("\u2717 Password is a commonly used password!")
        suggestions.append("Never use a well-known password \u2014 attackers try these first.")
    elif similar_words:
        details.append(f"\u2717 Password is similar to common password(s): "
                       f"{', '.join(similar_words[:3])}")
        suggestions.append("Avoid slight variations of common passwords (e.g. p@ssw0rd) \u2014 "
                           "attackers check these too.")
        dict_penalty = SIMILAR_PENALTY
    if dict_words and not is_exact:
        details.append(f"\u2717 Contains dictionary word(s): "
                       f"{', '.join(dict_words[:3])}")
        suggestions.append("Avoid embedding dictionary words \u2014 use random or nonsensical combinations instead.")
        dict_penalty = min(dict_penalty, DICT_WORD_PENALTY)

    # --- Combine scores -----------------------------------------------------
    raw_score = l_score + d_score + e_score + p_penalty + dict_penalty

    if is_exact:
        raw_score = min(raw_score, EXACT_COMMON_CAP)

    score = max(0, min(100, raw_score))

    # --- Label --------------------------------------------------------------
    if score <= 25:
        label = "Very Weak"
    elif score <= 50:
        label = "Weak"
    elif score <= 75:
        label = "Moderate"
    else:
        label = "Strong"

    result = EvaluationResult(
        score=score,
        label=label,
        details=details,
        suggestions=suggestions,
        entropy_bits=e_bits,
        crack_time=crack,
    )

    if len(_EVAL_CACHE) >= 32:
        _EVAL_CACHE.pop(next(iter(_EVAL_CACHE)))
    _EVAL_CACHE[password] = result

    return result


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

_ALL_CHARS = string.ascii_letters + string.digits + string.punctuation

def generate_password(length: int = 16) -> str:
    """
    Generate a cryptographically random password of *length* characters,
    guaranteed to contain at least one character from each category
    (lowercase, uppercase, digit, special).
    """
    length = max(length, 12)
    categories = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]
    password_chars = [secrets.choice(cat) for cat in categories]
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(_ALL_CHARS) for _ in range(remaining))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
