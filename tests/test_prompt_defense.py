"""Tests for static prompt-defence evaluator and system-prompt augmentation."""

from __future__ import annotations

import unittest

from cognexus import (
    GRADE_THRESHOLDS,
    VECTOR_COUNT,
    PromptDefenseEvaluator,
    augment_system_prompt,
    evaluate_system_prompt,
)


class StaticEvaluatorTests(unittest.TestCase):
    def test_minimal_prompt_grades_F(self) -> None:
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        self.assertEqual(report.total, VECTOR_COUNT)
        self.assertEqual(report.grade, "F")
        self.assertGreater(len(report.missing), 6)

    def test_fully_defended_prompt_grades_A(self) -> None:
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.missing, [])

    def test_audit_entry_denied_on_failing_prompt(self) -> None:
        evaluator = PromptDefenseEvaluator()
        report = evaluator.evaluate("You are a helpful assistant.")
        entry = evaluator.to_audit_entry(report, agent_did="agent:test")
        self.assertEqual(entry["outcome"], "denied")
        self.assertEqual(entry["event_type"], "prompt.defense.evaluated")

    def test_audit_entry_success_on_passing_prompt(self) -> None:
        evaluator = PromptDefenseEvaluator()
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = evaluator.evaluate(augmented)
        entry = evaluator.to_audit_entry(report, agent_did="agent:test")
        self.assertEqual(entry["outcome"], "success")

    def test_grade_thresholds_descending(self) -> None:
        previous = 101
        for grade, threshold in GRADE_THRESHOLDS.items():
            self.assertLess(threshold, previous, f"{grade}={threshold} not < {previous}")
            previous = threshold

    def test_to_dict_is_json_serialisable(self) -> None:
        import json
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        data = report.to_dict()
        self.assertIsInstance(json.dumps(data), str)

    def test_is_blocking_respects_min_grade(self) -> None:
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        self.assertFalse(report.is_blocking(min_grade="A"))

    def test_evaluate_file_raises_on_missing_file(self) -> None:
        evaluator = PromptDefenseEvaluator()
        with self.assertRaises(FileNotFoundError):
            evaluator.evaluate_file("/nonexistent/path/prompt.txt")

    def test_evaluate_batch(self) -> None:
        evaluator = PromptDefenseEvaluator()
        prompts = {
            "minimal": "You are a helpful assistant.",
            "augmented": augment_system_prompt("You are a helpful assistant."),
        }
        reports = evaluator.evaluate_batch(prompts)
        self.assertIn("minimal", reports)
        self.assertIn("augmented", reports)
        self.assertEqual(reports["minimal"].grade, "F")
        self.assertEqual(reports["augmented"].grade, "A")

    def test_augment_is_idempotent_on_empty(self) -> None:
        out_empty = augment_system_prompt("")
        out_none = augment_system_prompt(None)  # type: ignore[arg-type]
        self.assertTrue(out_empty)
        self.assertEqual(out_empty, out_none)

    def test_evaluate_system_prompt_wrapper(self) -> None:
        report = evaluate_system_prompt("You are a helpful assistant.")
        self.assertIsNotNone(report.grade)
        self.assertIsNotNone(report.prompt_hash)

    def test_appendix_defends_post_pocketos_vectors(self) -> None:
        """The vectors added in v0.2.0 in response to the PocketOS / Claude
        incident must be present on the augmented prompt: agents that *guess*
        on destructive ops, and operator awareness of the runtime kill switch."""
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        defended = {f.vector_id for f in report.findings if f.defended}
        self.assertIn("database-destruction", defended)
        self.assertIn("never-guess-destructive", defended)
        self.assertIn("kill-switch-awareness", defended)


class NeverGuessVectorTests(unittest.TestCase):
    """The new ``never-guess-destructive`` vector must require BOTH a refusal
    cue (never/refuse/do-not) AND a destructive-action cue."""

    def test_minimal_prompt_misses_never_guess(self) -> None:
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        missing = set(report.missing)
        self.assertIn("never-guess-destructive", missing)

    def test_explicit_never_guess_clause_is_defended(self) -> None:
        prompt = (
            "You are a helpful assistant. Never guess at parameters when an "
            "irreversible drop or delete is possible — refuse and ask the user."
        )
        report = PromptDefenseEvaluator().evaluate(prompt)
        defended = {f.vector_id for f in report.findings if f.defended}
        self.assertIn("never-guess-destructive", defended)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
