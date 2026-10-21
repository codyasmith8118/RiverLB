"""Exercise documentation validation using small temporary document trees."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check-docs.py"
SPEC = importlib.util.spec_from_file_location("check_docs", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DocumentationLinks(unittest.TestCase):
    def test_valid_relative_reference_and_encoded_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "docs").mkdir()
            (root / "docs/guide name.md").write_text("# Use `RiverLB`\n# Use `RiverLB`\n")
            (root / "README.md").write_text(
                "[Guide](<docs/guide name.md#use-riverlb>)\n"
                "[Again](docs/guide%20name.md#use-riverlb-1)\n"
                "[Reference][guide]\n[guide]: docs/guide%20name.md\n"
                "[Remote](https://example.test/not-checked)\n"
                "```markdown\n[Example](missing.md)\n```\n"
                "`[Inline example](also-missing.md)`\n")
            _, links, errors = CHECKER.check(root)
            self.assertEqual(links, 3)
            self.assertEqual(errors, [])

    def test_nested_guides_and_templates_are_checked_but_local_state_is_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for directory in ("deploy/ha/hyperv", ".github", "target", "dist", ".codex"):
                (root / directory).mkdir(parents=True)
                (root / directory / "guide.md").write_text("[Missing](absent.md)\n")
            (root / "SECURITY.md").write_text("[Missing](absent.md)\n")
            # Do not traverse symlinked local directories or documents.
            (root / "linked").symlink_to(root / "deploy", target_is_directory=True)
            (root / "linked.md").symlink_to(root / "SECURITY.md")
            documents, links, errors = CHECKER.check(root)
            self.assertEqual(documents, 3)
            self.assertEqual(links, 3)
            self.assertEqual(len(errors), 3)
            self.assertTrue(any("deploy/ha/hyperv" in error for error in errors))
            self.assertTrue(any(".github" in error for error in errors))

    def test_missing_files_headings_and_repository_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "README.md").write_text(
                "# Real heading\n[Missing](absent.md)\n[Anchor](#fictional)\n"
                "[Escape](../outside.md)\n[Code heading](#example-only)\n"
                "~~~text\n# Example only\n~~~\n")
            _, links, errors = CHECKER.check(root)
            self.assertEqual(links, 4)
            self.assertEqual(len(errors), 4)
            self.assertTrue(any("outside the repository" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
