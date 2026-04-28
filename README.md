# Password Strength Evaluation Tool

A Python-based desktop application that evaluates password strength using a hybrid scoring model combining rule-based analysis, Shannon entropy estimation, pattern detection, and dictionary comparison — all processed locally with no network required.

## Features

- **Hybrid 5-dimension scoring**: length, character diversity, entropy, pattern penalty, dictionary penalty → 0–100 score
- **Real-time analysis**: 300ms debounced feedback as you type
- **Pattern detection**: sequential characters, repeated characters, keyboard patterns (including reversed)
- **Dictionary comparison**: exact match, substring check, Levenshtein similarity
- **Animated visual indicators**: semicircular gauge + horizontal strength meter
- **Password generation**: cryptographically secure passwords using `secrets` module
- **Dark-themed GUI**: built with CustomTkinter
- **Privacy-first**: all processing is local, no passwords stored or transmitted

## Requirements

- Python 3.10+
- customtkinter >= 5.2.0

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m password_tool
```

Or on Windows, double-click `run.bat` — it will automatically create a virtual environment, install dependencies, and launch the application.

## Scoring Model

| Dimension | Range | Weight |
|-----------|-------|--------|
| Length | 0–25 | + |
| Character diversity | 0–25 | + |
| Entropy | 0–30 | + |
| Pattern penalty | 0 to −15 | − |
| Dictionary penalty | cap at 10 / −20 / −15 | − |

Final score is clamped to 0–100 and labeled:

| Score | Label |
|-------|-------|
| 0–25 | Very Weak |
| 26–50 | Weak |
| 51–75 | Moderate |
| 76–100 | Strong |

## Project Structure

```
password_tool/
├── __init__.py
├── __main__.py
├── main.py                 # CustomTkinter GUI
├── evaluator.py             # Scoring engine + password generation
├── entropy.py               # Entropy calculation + crack time estimation
├── patterns.py              # Sequential, repeated, keyboard pattern detection
├── dictionary_check.py      # Dictionary exact/substring/Levenshtein checks
└── common_passwords.txt     # 181-entry common password list
```

## License

Educational project — not intended for production security auditing.
