# Password Strength Checker

A command-line tool that evaluates password strength **locally**, flags common weaknesses and suggests improvements. Built for the CodeNova Cyber Security Internship (Task 1).

## Privacy guarantee

- The password is typed with hidden input (`getpass`) and analysed **only in volatile memory**.
- It is **never** written to a file, logged, printed back or sent over a network.
- The tool has no file-writing or network code, and the results object never contains the password.
- Do not pass passwords as command-line arguments: shells keep history.

The unit tests enforce this: file access (`open`) and network sockets are replaced with functions that fail the test if called.

## Features

- Length and character variety (lowercase, uppercase, digits, special characters)
- Shannon-style entropy estimate
- Common-password dictionary check
- Weak-substitution detection (`p@ssword`, `P4ssw0rd`)
- Repeated characters/blocks (`aaa`, `abab`) and predictable sequences (`1234`, `abcd`, `qwer`)
- Year detection (`2024`) and short-password detection
- Clear rating, 0-100 score and actionable suggestions

## Entropy and scoring

```
entropy (bits) = length x log2(pool_size)
```

`pool_size` is the sum of the character sets used:

| Character set | Added to pool |
|---|---|
| Lowercase a-z | 26 |
| Uppercase A-Z | 26 |
| Digits 0-9 | 10 |
| Symbols and space | 32 |
| Non-ASCII characters | 32 |

Example: 8 lowercase letters give 8 x log2(26) = 37.6 bits.

This is an upper-bound estimate that assumes random characters. Predictable choices are therefore **penalised** to produce an *adjusted entropy*:

| Finding | Effect on adjusted entropy |
|---|---|
| Exactly a common password | capped at 5 bits |
| Common word with look-alike substitutions | capped at 8 bits |
| Contains a common password/word (5+ letters) | minus 25 |
| Sequence of 4+ characters | minus 12 |
| Repeated characters or blocks | minus 10 |
| Looks like a year (19xx / 20xx) | minus 5 |
| Fewer than 8 characters | capped at 35 bits |

| Adjusted entropy | Rating |
|---|---|
| below 28 | Very Weak |
| 28 to 35.9 | Weak |
| 36 to 59.9 | Moderate |
| 60 to 79.9 | Strong |
| 80 and above | Very Strong |

`score = min(100, adjusted_entropy / 80 x 100)`

## Requirements

- Python 3.8 or newer (Windows, macOS or Linux)
- No external packages

## Usage

```
python task1.py
```

Type a password (nothing appears while typing) and press Enter. Press Enter on an empty line to quit.

## Tests

```
python -m unittest -v test_task1.py
```

The suite covers weak, moderate and strong passwords, leetspeak, sequences, repetition, the entropy formula, empty input, and the no-storage/no-network guarantee.

## Project files

```
task1.py          main tool
test_task1.py     unit tests
README.md         this file
```

## Screenshots

Add your own screenshots of a real run (use throwaway passwords only):

<img width="687" height="141" alt="WhatsApp Image 2026-10-22 at 3 40 09 AM" src="https://github.com/user-attachments/assets/0eca8b4e-a93d-4202-a902-f65f80389f27" />
<img width="808" height="210" alt="WhatsApp Image 2026-10-22 at 3 41 31 AM" src="https://github.com/user-attachments/assets/a07f10e3-03e7-4f02-a18f-0c5bf14ad149" />
<img width="771" height="233" alt="WhatsApp Image 2026-10-22 at 3 42 21 AM" src="https://github.com/user-attachments/assets/0e1b0cd4-a4a9-4551-b8cc-b9b8cc9c5bae" />
<img width="785" height="244" alt="WhatsApp Image 2026-10-22 at 3 43 19 AM" src="https://github.com/user-attachments/assets/22cc7c4a-3739-4adb-8196-35427b0bbfc8" />
<img width="825" height="221" alt="WhatsApp Image 2026-10-22 at 3 47 33 AM" src="https://github.com/user-attachments/assets/21d595b8-65e5-411d-86b4-6e889b9306c3" />






## Limitations

- The built-in dictionary is small. Real attackers use far larger lists, so a "Strong" rating is not a guarantee.
- Entropy is an estimate, not a proof of security.
- Use a unique password per site and a password manager.
