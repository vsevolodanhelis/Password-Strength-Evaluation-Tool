"""
Password Strength Evaluation Tool
==================================
A hybrid password strength evaluation system combining rule-based
analysis, entropy estimation, dictionary comparison, and pattern detection.
"""

__version__ = "1.0.0"

__all__ = [
    "evaluate_password",
    "EvaluationResult",
    "generate_password",
    "calculate_entropy",
    "classify_characters",
    "entropy_score",
    "estimate_crack_time",
    "is_common_password",
    "contains_dictionary_word",
    "is_similar_to_common",
    "levenshtein_distance",
    "detect_sequential",
    "detect_repeated",
    "detect_keyboard_patterns",
    "detect_all_patterns",
    "pattern_penalty_from_result",
    "PasswordAnalyzerApp",
]

from password_tool.evaluator import evaluate_password, EvaluationResult, generate_password
from password_tool.entropy import (
    calculate_entropy,
    classify_characters,
    entropy_score,
    estimate_crack_time,
)
from password_tool.dictionary_check import (
    is_common_password,
    contains_dictionary_word,
    is_similar_to_common,
    levenshtein_distance,
)
from password_tool.patterns import (
    detect_sequential,
    detect_repeated,
    detect_keyboard_patterns,
    detect_all_patterns,
    pattern_penalty_from_result,
)
