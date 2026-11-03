from safety_checker import (
    SafeEvaluator
)


def main():
    result = SafeEvaluator().eval(
        """
import os
os.system("cls")
"""
    )

    print(result)


if __name__ == "__main__":
    main()