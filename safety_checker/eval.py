import ast
import math
import operator


class SafeEvalError(Exception):
    pass


class SafeEvaluator:
    MAX_EXPRESSION_LENGTH = 1000
    MAX_AST_NODES = 100
    MAX_POWER_BASE = 1000
    MAX_POWER_EXPONENT = 1000
    MAX_RESULT = 1e308
    MAX_FUNCTION_ARGS = 10

    def __init__(self):
        self.allowed_operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Pow: operator.pow,
            ast.Mod: operator.mod,
            ast.USub: operator.neg,
            ast.UAdd: operator.pos,
        }

        self.allowed_functions = {
            "abs": abs,
            "round": round,
            "min": min,
            "max": max,
            "sqrt": math.sqrt,
            "sin": math.sin,
            "cos": math.cos,
            "tan": math.tan,
            "acos": math.acos,
            "asin": math.asin,
            "atan": math.atan,
            "log": math.log,
            "exp": math.exp,
            "pow": math.pow,
        }

        self.allowed_names = {
            "pi": math.pi,
            "e": math.e,
            "tau": math.tau,
        }

    def eval(self, expr: str):
        if not isinstance(expr, str):
            raise SafeEvalError("Expression must be a string.")

        expr = expr.strip()

        if not expr:
            raise SafeEvalError("Expression cannot be empty.")

        if len(expr) > self.MAX_EXPRESSION_LENGTH:
            raise SafeEvalError(
                f"Expression is too long. Maximum length is "
                f"{self.MAX_EXPRESSION_LENGTH} characters."
            )

        try:
            parsed_ast = ast.parse(expr, mode="eval")
        except SyntaxError as exc:
            raise SafeEvalError(
                f"SyntaxError: {exc.msg}"
            ) from None

        node_count = sum(1 for _ in ast.walk(parsed_ast))

        if node_count > self.MAX_AST_NODES:
            raise SafeEvalError(
                f"Expression is too complex. Maximum AST nodes: "
                f"{self.MAX_AST_NODES}."
            )

        try:
            result = self._eval_node(parsed_ast.body)
            self._validate_result(result)
            return result

        except SafeEvalError:
            raise

        except ZeroDivisionError:
            raise SafeEvalError(
                "Division by zero is not allowed."
            ) from None

        except (ValueError, OverflowError, TypeError) as exc:
            raise SafeEvalError(
                f"Invalid mathematical operation: {exc}"
            ) from None

    def _eval_node(self, node):
        if isinstance(node, ast.Constant):
            if type(node.value) in (int, float):
                return node.value

            raise SafeEvalError(
                f"Invalid constant type: {type(node.value).__name__}"
            )

        if isinstance(node, ast.Name):
            if node.id in self.allowed_names:
                return self.allowed_names[node.id]

            raise SafeEvalError(
                f"Undefined name: '{node.id}'"
            )

        if isinstance(node, ast.BinOp):
            op_type = type(node.op)

            if op_type not in self.allowed_operators:
                raise SafeEvalError(
                    f"Unsupported operator: {op_type.__name__}"
                )

            left = self._eval_node(node.left)
            right = self._eval_node(node.right)

            if op_type is ast.Pow:
                self._validate_power(left, right)

            result = self.allowed_operators[op_type](left, right)
            self._validate_result(result)

            return result

        if isinstance(node, ast.UnaryOp):
            op_type = type(node.op)

            if op_type not in self.allowed_operators:
                raise SafeEvalError(
                    f"Unsupported unary operator: {op_type.__name__}"
                )

            operand = self._eval_node(node.operand)
            result = self.allowed_operators[op_type](operand)

            self._validate_result(result)

            return result

        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise SafeEvalError(
                    "Nested or dynamic function calls are not supported."
                )

            if node.keywords:
                raise SafeEvalError(
                    "Keyword arguments are not supported."
                )

            function_name = node.func.id

            if function_name not in self.allowed_functions:
                raise SafeEvalError(
                    f"Unsupported or unsafe function: "
                    f"'{function_name}()'"
                )

            if len(node.args) > self.MAX_FUNCTION_ARGS:
                raise SafeEvalError(
                    f"Too many function arguments. Maximum allowed: "
                    f"{self.MAX_FUNCTION_ARGS}."
                )

            args = [
                self._eval_node(arg)
                for arg in node.args
            ]

            try:
                result = self.allowed_functions[function_name](*args)
            except (ValueError, OverflowError, TypeError) as exc:
                raise SafeEvalError(
                    f"Invalid operation in {function_name}(): {exc}"
                ) from None

            self._validate_result(result)

            return result

        raise SafeEvalError(
            f"Unsafe syntax structure: {type(node).__name__}"
        )

    def _validate_power(self, base, exponent):
        if not math.isfinite(float(base)):
            raise SafeEvalError(
                "Power base must be finite."
            )

        if not math.isfinite(float(exponent)):
            raise SafeEvalError(
                "Power exponent must be finite."
            )

        if abs(base) > self.MAX_POWER_BASE:
            raise SafeEvalError(
                f"Power base is too large. Maximum absolute value: "
                f"{self.MAX_POWER_BASE}."
            )

        if abs(exponent) > self.MAX_POWER_EXPONENT:
            raise SafeEvalError(
                f"Power exponent is too large. Maximum absolute value: "
                f"{self.MAX_POWER_EXPONENT}."
            )

        if base == 0 and exponent < 0:
            raise SafeEvalError(
                "Zero cannot be raised to a negative power."
            )

    def _validate_result(self, result):
        if type(result) not in (int, float):
            raise SafeEvalError(
                f"Invalid result type: {type(result).__name__}"
            )

        if isinstance(result, float):
            if math.isnan(result):
                raise SafeEvalError(
                    "The result is NaN."
                )

            if math.isinf(result):
                raise SafeEvalError(
                    "The result is infinite."
                )

            if abs(result) > self.MAX_RESULT:
                raise SafeEvalError(
                    "The result is too large."
                )

        if isinstance(result, int):
            if len(str(abs(result))) > 1000:
                raise SafeEvalError(
                    "The integer result is too large."
                )