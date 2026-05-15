from pathlib import Path
import unittest


class GeminiPromptSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = Path("backend/app/services/gemini.py").read_text(encoding="utf-8")

    def test_prompt_documents_slither_only_constraint(self):
        self.assertIn("You must ONLY interpret findings that Slither already reported", self.source)
        self.assertIn("Do not create, infer, or invent additional vulnerabilities", self.source)

    def test_prompt_uses_contract_delimiters(self):
        self.assertIn("###CONTRACT###", self.source)
        self.assertIn("Use only this Slither finding", self.source)


if __name__ == "__main__":
    unittest.main()
