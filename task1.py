"""
task1.py - Password Strength Checker (CodeNova Cyber Security Internship, Task 1)

What it does:
  * Evaluates a password's length, character variety and Shannon-style entropy
  * Detects common passwords, leetspeak tricks (p@ssword), repeated characters,
    and predictable sequences (123456, abcd, qwerty)
  * Gives clear suggestions for improvement

Privacy guarantee:
  The password is read with getpass (hidden input), analysed only in memory,
  and is NEVER written to disk, logged, printed back, or sent over a network.
  Run: python task1.py   (do not pass passwords as command-line arguments,
  because shells keep command history).

Entropy formula:
  entropy (bits) = length * log2(pool_size)
  pool_size = sum of the character sets used (lowercase 26, uppercase 26,
  digits 10, symbols 32, other characters 32). This is an UPPER-BOUND estimate;
  predictable passwords are penalised below.
"""

import getpass
import math
import os
import re
import string
import sys

# A small built-in dictionary of very common passwords/words (lowercase).
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "123456", "1234567",
    "12345678", "123456789", "1234567890", "12345", "111111", "000000",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "letmein", "welcome",
    "welcome1", "admin", "admin123", "login", "iloveyou", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "baseball", "superman",
    "batman", "trustno1", "shadow", "michael", "jennifer", "hello", "hello123",
    "freedom", "whatever", "secret", "changeme", "default", "guest", "root",
    "toor", "test", "test123", "zaq12wsx", "1q2w3e4r", "asdfgh", "asdfghjkl",
    "zxcvbnm", "flower", "lovely", "ashley", "bailey", "charlie", "donald",
    "mustang", "access", "starwars", "cheese", "computer", "internet",
    "google", "summer", "winter", "spring", "autumn", "pass", "user",
})

# Sources of predictable sequences (each is also checked reversed).
SEQUENCE_SOURCES = [
    string.ascii_lowercase,
    string.digits,
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
]

# Common character substitutions used by people ("leetspeak").
LEET_MAP = {"@": "a", "4": "a", "3": "e", "!": "i", "0": "o",
            "$": "s", "5": "s", "7": "t", "+": "t"}


def character_pool_size(password):
    """Return the size of the character pool the password draws from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        pool += 32
    if any(not c.isascii() for c in password):
        pool += 32
    return pool


def calculate_entropy(password):
    """Shannon-style entropy estimate in bits: length * log2(pool size)."""
    pool = character_pool_size(password)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def leet_variants(password):
    """Return versions of the password with common substitutions reversed."""
    base = "".join(LEET_MAP.get(c, c) for c in password.lower())
    return {base, base.replace("1", "i"), base.replace("1", "l")}


def has_sequence(password, min_len=4):
    """True if the password contains a run like 1234, abcd, dcba or qwer."""
    pw = password.lower()
    for i in range(len(pw) - min_len + 1):
        chunk = pw[i:i + min_len]
        for source in SEQUENCE_SOURCES:
            if chunk in source or chunk in source[::-1]:
                return True
    return False
def has_repetition(password):
    """True for runs like 'aaa' or repeated blocks like 'abab' / '123123'."""
    return bool(re.search(r"(.)\1{2,}", password)
                or re.search(r"(.{2,4})\1+", password))


def analyze_password(password):
    """
    Analyse a password entirely in memory.
    Returns a dict of results. The password itself is never included in it.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    flags = set()
    findings = []
    suggestions = []
    lowered = password.lower()
    variants = leet_variants(password)

    # --- Basic composition ---
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    entropy = calculate_entropy(password)
    effective = entropy

    # --- Dictionary / substitution checks ---
    if lowered in COMMON_PASSWORDS:
        flags.add("common")
        findings.append("This is one of the most commonly used passwords.")
        effective = min(effective, 5)
    elif any(v in COMMON_PASSWORDS for v in variants):
        flags.add("leet_common")
        findings.append("Weak substitution: swapping letters for look-alike "
                        "symbols (e.g. @ for a) on a common word is easy for "
                        "attackers to guess.")
        effective = min(effective, 8)
    elif any(w in v for v in variants | {lowered}
             for w in COMMON_PASSWORDS if len(w) >= 5):
        flags.add("contains_common")
        findings.append("Contains a very common password or word.")
        effective -= 25

    # --- Pattern checks ---
    if has_sequence(password):
        flags.add("sequence")
        findings.append("Contains a predictable sequence (such as 1234, "
                        "abcd or qwer).")
        effective -= 12
    if has_repetition(password):
        flags.add("repeat")
        findings.append("Contains repeated characters or repeated blocks.")
        effective -= 10
    if re.search(r"(19|20)\d{2}", password):
        flags.add("year")
        findings.append("Contains something that looks like a year, which "
                        "is a common guess.")
        effective -= 5
    if len(password) < 8:
        flags.add("short")
        findings.append("Shorter than 8 characters.")
        effective = min(effective, 35)

    effective = max(0.0, round(effective, 1))

    # --- Rating ---
    if effective < 28:
        rating = "Very Weak"
    elif effective < 36:
        rating = "Weak"
    elif effective < 60:
        rating = "Moderate"
    elif effective < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"
    score = min(100, int(effective / 80 * 100))

    # --- Suggestions ---
    if len(password) < 12:
        suggestions.append("Use at least 12 characters; a passphrase of 4+ "
                           "random words is easy to remember and strong.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_digit:
        suggestions.append("Add numbers.")
    if not has_symbol:
        suggestions.append("Add special characters (e.g. ! ? # %).")
    if flags & {"common", "leet_common", "contains_common"}:
        suggestions.append("Avoid dictionary words and common passwords, "
                           "even with substitutions.")
    if "sequence" in flags:
        suggestions.append("Avoid keyboard or alphabet/number sequences.")
    if "repeat" in flags:
        suggestions.append("Avoid repeating characters or blocks.")
    if "year" in flags:
        suggestions.append("Avoid birth years and other guessable dates.")
    suggestions.append("Use a unique password for every account and store "
                       "them in a password manager.")

    return {
        "length": len(password),
        "has_lower": has_lower, "has_upper": has_upper,
        "has_digit": has_digit, "has_symbol": has_symbol,
        "pool_size": character_pool_size(password),
        "entropy_bits": entropy,
        "effective_entropy_bits": effective,
        "score": score,
        "rating": rating,
        "flags": flags,
        "findings": findings,
        "suggestions": suggestions,
    }


# ----------------------------- Terminal output -----------------------------

def _enable_ansi():
    """Make colours work in the Windows terminal."""
    if os.name == "nt":
        os.system("")


COLOURS = {"Very Weak": "\033[91m", "Weak": "\033[91m", "Moderate": "\033[93m",
           "Strong": "\033[92m", "Very Strong": "\033[96m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def print_report(result):
    colour = COLOURS[result["rating"]]
    filled = result["score"] // 5
    bar = "#" * filled + "-" * (20 - filled)
    yes_no = lambda ok: "Yes" if ok else "No"

    print()
    print(f"{BOLD}PASSWORD STRENGTH REPORT{RESET}")
    print("=" * 50)
    print(f"Rating  : {colour}{BOLD}{result['rating']}{RESET}")
    print(f"Score   : [{colour}{bar}{RESET}] {result['score']}/100")
    print("-" * 50)
    print(f"Length            : {result['length']}")
    print(f"Lowercase letters : {yes_no(result['has_lower'])}")
    print(f"Uppercase letters : {yes_no(result['has_upper'])}")
    print(f"Numbers           : {yes_no(result['has_digit'])}")
    print(f"Special characters: {yes_no(result['has_symbol'])}")
    print(f"Character pool    : {result['pool_size']}")
    print(f"Entropy           : {result['entropy_bits']} bits "
          f"(adjusted for weaknesses: {result['effective_entropy_bits']} bits)")
    print("-" * 50)
    if result["findings"]:
        print(f"{BOLD}Weaknesses found{RESET}")
        for item in result["findings"]:
            print(f"  [!] {item}")
    else:
        print("No predictable patterns detected.")
    print(f"{BOLD}Suggestions{RESET}")
    for item in result["suggestions"]:
        print(f"  [+] {item}")
    print("=" * 50)
    print(f"{DIM}Your password was analysed in memory only and was not "
          f"stored, logged or transmitted.{RESET}")


def main():
    _enable_ansi()
    print(f"{BOLD}Password Strength Checker{RESET}")
    print("Typing is hidden. Press Enter on an empty line to quit.\n")
    while True:
        try:
            password = getpass.getpass("Enter a password to check: ")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            return 0
        if password == "":
            print("Goodbye.")
            return 0
        print_report(analyze_password(password))
        print()


if __name__ == "__main__":
    sys.exit(main())