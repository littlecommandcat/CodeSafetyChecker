import ast
from .objects import Issue, Rule
from .utils import get_source_line

class DangerousFunctionRule(Rule):
    rule_id = "SEC001"
    severity = "ERROR"

    dangerous_functions = {
        "eval": "Avoid eval(); it can execute arbitrary Python code.",
        "exec": "Avoid exec(); it can execute arbitrary Python code.",
        "compile": "Avoid compile(); it can dynamically create executable code.",
        "__import__": "Avoid dynamic imports through __import__().",
    }

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if isinstance(node.func, ast.Name):
                name = node.func.id

                if name in self.dangerous_functions:
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            self.dangerous_functions[name],
                            filename,
                            node.lineno,
                            node.col_offset,
                            get_source_line(source, node.lineno),
                        )
                    )

        return issues


class DangerousImportRule(Rule):
    rule_id = "SEC002"
    severity = "ERROR"

    dangerous_modules = {
        "pickle",
        "marshal",
        "shelve",
        "subprocess",
        "ctypes",
    }

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]

                    if module in self.dangerous_modules:
                        issues.append(
                            Issue(
                                self.rule_id,
                                self.severity,
                                f"Potentially dangerous module imported: {alias.name}",
                                filename,
                                node.lineno,
                                node.col_offset,
                                get_source_line(source, node.lineno),
                            )
                        )

            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]

                if module in self.dangerous_modules:
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            f"Potentially dangerous module imported: {node.module}",
                            filename,
                            node.lineno,
                            node.col_offset,
                            get_source_line(source, node.lineno),
                        )
                    )

        return issues


class ShellExecutionRule(Rule):
    rule_id = "SEC003"
    severity = "ERROR"

    shell_functions = {
        "system",
        "popen",
        "spawn",
    }

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr in self.shell_functions:
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        f"Potential shell execution through '{node.func.attr}()'.",
                        filename,
                        node.lineno,
                        node.col_offset,
                        get_source_line(source, node.lineno),
                    )
                )

        return issues


class HardcodedPasswordRule(Rule):
    rule_id = "SEC004"
    severity = "WARNING"

    sensitive_names = {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
    }

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            if not isinstance(node.value, ast.Constant):
                continue

            if not isinstance(node.value.value, str):
                continue

            value = node.value.value

            if not value:
                continue

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue

                name = target.id.lower()

                if any(key in name for key in self.sensitive_names):
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            f"Possible hardcoded secret in variable '{target.id}'.",
                            filename,
                            node.lineno,
                            node.col_offset,
                            get_source_line(source, node.lineno),
                        )
                    )

        return issues


class MutableDefaultArgumentRule(Rule):
    rule_id = "PY001"
    severity = "WARNING"

    def check(self, tree, source, filename):
        issues = []

        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        for node in functions:
            defaults = list(node.args.defaults)

            defaults.extend(
                default
                for default in node.args.kw_defaults
                if default is not None
            )

            for default in defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            "Mutable default argument detected. "
                            "Use None and create the object inside the function.",
                            filename,
                            default.lineno,
                            default.col_offset,
                            get_source_line(source, default.lineno),
                        )
                    )

        return issues


class BareExceptRule(Rule):
    rule_id = "PY002"
    severity = "WARNING"

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            "Bare except detected. Catch a specific exception.",
                            filename,
                            node.lineno,
                            node.col_offset,
                            get_source_line(source, node.lineno),
                        )
                    )

        return issues


class AssertRule(Rule):
    rule_id = "PY003"
    severity = "INFO"

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        "assert may be removed when Python runs with optimization.",
                        filename,
                        node.lineno,
                        node.col_offset,
                        get_source_line(source, node.lineno),
                    )
                )

        return issues


class TooManyArgumentsRule(Rule):
    rule_id = "DES001"
    severity = "WARNING"

    MAX_ARGUMENTS = 8

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            args = node.args

            count = (
                len(args.posonlyargs)
                + len(args.args)
                + len(args.kwonlyargs)
            )

            if args.vararg:
                count += 1

            if args.kwarg:
                count += 1

            if count > self.MAX_ARGUMENTS:
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        f"Function '{node.name}' has {count} arguments. "
                        f"Consider reducing it to {self.MAX_ARGUMENTS} or fewer.",
                        filename,
                        node.lineno,
                        node.col_offset,
                        get_source_line(source, node.lineno),
                    )
                )

        return issues


class FunctionLengthRule(Rule):
    rule_id = "DES002"
    severity = "WARNING"

    MAX_LINES = 50

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            if not hasattr(node, "end_lineno"):
                continue

            length = node.end_lineno - node.lineno + 1

            if length > self.MAX_LINES:
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        f"Function '{node.name}' is {length} lines long. "
                        f"Consider splitting it into smaller functions.",
                        filename,
                        node.lineno,
                        node.col_offset,
                        get_source_line(source, node.lineno),
                    )
                )

        return issues


class NestedDepthRule(Rule):
    rule_id = "DES003"
    severity = "WARNING"

    MAX_DEPTH = 4

    def check(self, tree, source, filename):
        issues = []

        def calculate_depth(node, depth=0):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.With,
                    ast.AsyncWith,
                    ast.Try,
                ),
            ):
                depth += 1

            max_depth = depth

            for child in ast.iter_child_nodes(node):
                max_depth = max(
                    max_depth,
                    calculate_depth(child, depth),
                )

            return max_depth

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = calculate_depth(node)

                if depth > self.MAX_DEPTH:
                    issues.append(
                        Issue(
                            self.rule_id,
                            self.severity,
                            f"Function '{node.name}' has nesting depth "
                            f"{depth}. Maximum recommended depth is "
                            f"{self.MAX_DEPTH}.",
                            filename,
                            node.lineno,
                            node.col_offset,
                            get_source_line(source, node.lineno),
                        )
                    )

        return issues


class ComplexityRule(Rule):
    rule_id = "DES004"
    severity = "WARNING"

    MAX_COMPLEXITY = 10

    def check(self, tree, source, filename):
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            complexity = 1

            for child in ast.walk(node):
                if isinstance(
                    child,
                    (
                        ast.If,
                        ast.For,
                        ast.AsyncFor,
                        ast.While,
                        ast.ExceptHandler,
                        ast.With,
                        ast.AsyncWith,
                        ast.IfExp,
                    ),
                ):
                    complexity += 1

                elif isinstance(child, ast.BoolOp):
                    complexity += max(0, len(child.values) - 1)

            if complexity > self.MAX_COMPLEXITY:
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        f"Function '{node.name}' has cyclomatic "
                        f"complexity {complexity}.",
                        filename,
                        node.lineno,
                        node.col_offset,
                        get_source_line(source, node.lineno),
                    )
                )

        return issues


class TodoRule(Rule):
    rule_id = "STYLE001"
    severity = "INFO"

    def check(self, tree, source, filename):
        issues = []

        for index, line in enumerate(source.splitlines(), start=1):
            if "TODO" in line.upper():
                issues.append(
                    Issue(
                        self.rule_id,
                        self.severity,
                        "TODO comment found.",
                        filename,
                        index,
                        0,
                        line,
                    )
                )

        return issues


class DuplicateConstantRule(Rule):
    rule_id = "STYLE002"
    severity = "INFO"

    def check(self, tree, source, filename):
        issues = []
        constants = {}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue

            if not isinstance(node.value, (str, int, float)):
                continue

            value = node.value

            if isinstance(value, str) and not value:
                continue

            constants.setdefault(value, []).append(node)

        for value, nodes in constants.items():
            if len(nodes) < 4:
                continue

            first = nodes[0]

            issues.append(
                Issue(
                    self.rule_id,
                    self.severity,
                    f"Constant {value!r} appears {len(nodes)} times. "
                    "Consider extracting it into a constant.",
                    filename,
                    first.lineno,
                    first.col_offset,
                    get_source_line(source, first.lineno),
                )
            )

        return issues