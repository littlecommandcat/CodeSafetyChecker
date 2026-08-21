import json
from .objects import Issue


def get_source_line(source: str, line_number: int=None) -> str:
    if not line_number:
        return ""

    lines = source.splitlines()

    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]

    return ""


def print_report(issues: list[Issue] = []):
    if not issues:
        print("No issues found.")
        return

    severity_colors = {
        "ERROR": "\033[91m",
        "WARNING": "\033[93m",
        "INFO": "\033[94m",
    }

    reset = "\033[0m"

    for issue in issues:
        color = severity_colors.get(
            issue.severity,
            "",
        )

        print(
            f"{color}"
            f"{issue.filename}:{issue.line}:{issue.column} "
            f"[{issue.severity}] "
            f"{issue.rule_id}: "
            f"{issue.message}"
            f"{reset}"
        )

        if issue.source:
            print(f"    {issue.source.strip()}")

    counts = {
        "ERROR": 0,
        "WARNING": 0,
        "INFO": 0,
    }

    for issue in issues:
        counts[issue.severity] = (
            counts.get(issue.severity, 0) + 1
        )

    print(
        f"Summary: "
        f"{counts.get('ERROR', 0)} errors, "
        f"{counts.get('WARNING', 0)} warnings, "
        f"{counts.get('INFO', 0)} info"
    )


def print_json_report(issues: list[Issue] = []):
    print(
        json.dumps(
            [issue.to_dict() for issue in issues],
            indent=2,
            ensure_ascii=False,
        )
    )