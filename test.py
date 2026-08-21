from safety_checker import (
    CodeChecker,
    DangerousImportRule,
    ShellExecutionRule,
    print_json_report
)


def main():
    checker = CodeChecker(
        rules=[
            DangerousImportRule,
            ShellExecutionRule,
        ]
    )

    result = checker.check(
        """
import os
os.system("cls")
"""
    )

    print_json_report(result)


if __name__ == "__main__":
    main()