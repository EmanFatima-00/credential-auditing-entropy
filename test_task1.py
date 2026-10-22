"""Unit tests for task1.py. Run with: python -m unittest -v test_task1.py"""

import unittest
from unittest import mock

from task1 import analyze_password


class TestWeakPasswords(unittest.TestCase):
    def test_common_passwords_are_very_weak(self):
        for pw in ["password", "123456", "qwerty"]:
            with self.subTest(pw=pw):
                result = analyze_password(pw)
                self.assertEqual(result["rating"], "Very Weak")
                self.assertIn("common", result["flags"])

    def test_leetspeak_substitution_detected(self):
        result = analyze_password("p@ssword")
        self.assertIn("leet_common", result["flags"])
        self.assertIn(result["rating"], ("Very Weak", "Weak"))

    def test_sequence_detected(self):
        self.assertIn("sequence", analyze_password("xyzabcd9K")["flags"])

    def test_repetition_detected(self):
        self.assertIn("repeat", analyze_password("Zebra!!!!99")["flags"])

    def test_common_word_with_extras_is_penalised(self):
        result = analyze_password("Summer2024!")
        self.assertIn("contains_common", result["flags"])
        self.assertLess(result["effective_entropy_bits"],
                        result["entropy_bits"])


class TestModerateAndStrong(unittest.TestCase):
    def test_moderate_password(self):
        result = analyze_password("Sunrise42")
        self.assertEqual(result["rating"], "Moderate")
        self.assertEqual(result["flags"], set())

    def test_strong_password(self):
        result = analyze_password("k9#Vx2!qLr7$Zp4wB")
        self.assertEqual(result["rating"], "Very Strong")
        self.assertEqual(result["flags"], set())

    def test_entropy_formula(self):
        # 8 lowercase letters: 8 * log2(26) = 37.6 bits
        self.assertEqual(analyze_password("kqzmwxvb")["entropy_bits"], 37.6)


class TestInputAndPrivacy(unittest.TestCase):
    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            analyze_password("")

    def test_result_never_contains_password(self):
        pw = "k9#Vx2!qLr7$Zp4wB"
        self.assertNotIn(pw, str(analyze_password(pw)))

    def test_no_file_or_network_access(self):
        # Any attempt to open a file or a network socket fails the test.
        with mock.patch("builtins.open", side_effect=AssertionError("file!")), \
             mock.patch("socket.socket", side_effect=AssertionError("net!")):
            analyze_password("S0me-Test#Password")


if __name__ == "__main__":
    unittest.main()