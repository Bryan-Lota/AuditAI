import unittest

from backend.app.services.pragma import read_pragma, select_installable_solc_version


class PragmaParsingTests(unittest.TestCase):
    def test_reads_pragma_expression(self):
        source = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        contract Demo {}
        """
        self.assertEqual(read_pragma(source), "^0.8.20")

    def test_selects_highest_explicit_version(self):
        self.assertEqual(select_installable_solc_version(">=0.7.0 <0.8.21"), "0.8.21")

    def test_missing_pragma_returns_none(self):
        self.assertIsNone(read_pragma("contract Demo {}"))
        self.assertIsNone(select_installable_solc_version(None))


if __name__ == "__main__":
    unittest.main()
