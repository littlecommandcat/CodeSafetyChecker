from dataclasses import dataclass, asdict

@dataclass
class Issue:
    rule_id: str
    severity: str
    message: str
    filename: str
    line: int
    column: int
    source: str = ""

    def to_dict(self):
        return asdict(self)

class Rule:
    rule_id = "RULE000"
    severity = "INFO"

    def check(self, tree, source, filename):
        raise NotImplementedError