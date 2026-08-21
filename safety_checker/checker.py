import ast

from .objects import Issue
from .rules import Rule


class CodeChecker:
    def __init__(self, rules: list[type[Rule]]):
        self.rules = [rule() for rule in rules]

    def check(self, source: str, filename: str = "<string>") -> list[Issue]:
        if not isinstance(source, str):
            raise TypeError("source must be a string")

        try:
            tree = ast.parse(
                source,
                filename=filename,
                mode="exec",
            )
        except SyntaxError as exc:
            return [
                Issue(
                    "SYNTAX001",
                    "ERROR",
                    f"Syntax error: {exc.msg}",
                    filename,
                    exc.lineno or 0,
                    exc.offset or 0,
                    self._get_source_line(
                        source,
                        exc.lineno or 0,
                    ),
                )
            ]

        issues = []

        for rule in self.rules:
            try:
                rule_issues = rule.check(
                    tree,
                    source,
                    filename,
                )

                if rule_issues:
                    issues.extend(rule_issues)

            except Exception as exc:
                issues.append(
                    Issue(
                        "INTERNAL001",
                        "ERROR",
                        f"Rule {rule.rule_id} failed: {exc}",
                        filename,
                        0,
                        0,
                    )
                )

        return sorted(
            issues,
            key=lambda issue: (
                issue.line,
                issue.column,
                issue.rule_id,
            ),
        )

    @staticmethod
    def _get_source_line(source: str, line_number: int) -> str:
        if line_number <= 0:
            return ""

        lines = source.splitlines()

        if line_number > len(lines):
            return ""

        return lines[line_number - 1]