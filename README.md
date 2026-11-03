# Safety Checker

A lightweight Python toolkit for checking source code with the Abstract Syntax Tree (AST) and evaluating restricted mathematical expressions. Uses only the Python standard library.

## Features

- **Security checks:** Flag potentially dangerous function calls, imports, shell execution, and hardcoded passwords.
- **Code quality checks:** Detect mutable default arguments, bare `except` blocks, `assert` statements, long functions, excessive arguments, deep nesting, and high complexity.
- **Style checks:** Find TODO markers and repeated constants.
- **Flexible rules and reports:** Choose which rules to run, add custom rules, and print readable or JSON reports with severity levels and source locations. Syntax errors are also reported.
- **Restricted math evaluation:** Evaluate arithmetic expressions with allowlisted functions such as `sqrt`, `sin`, and `log`, plus constants such as `pi` and `e`. Includes expression size and numeric result limits.

## Quick Start

Run this example from the repository root using Python 3.9 or later:

```python
from safety_checker import CodeChecker, SafeEvaluator, print_report
from safety_checker.rules import DangerousFunctionRule, ShellExecutionRule

checker = CodeChecker(rules=[DangerousFunctionRule, ShellExecutionRule])
issues = checker.check('eval("1 + 1")', filename="example.py")
print_report(issues)

result = SafeEvaluator().eval("sqrt(16) + 2 ** 3")
print(result)  # 12.0
```

Use `print_json_report(issues)` instead of `print_report(issues)` for JSON output.

> Static checks can miss unsafe code or flag harmless patterns. This toolkit is not a security sandbox and does not guarantee that code is safe to execute.

