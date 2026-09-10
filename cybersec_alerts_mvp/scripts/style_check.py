"""Small dependency-free Google-style guardrail for the rough-draft MVP."""

from __future__ import annotations

import ast
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
MAX_LINE_LENGTH = 80


def main() -> int:
    """Checks line hygiene and public API docstrings."""
    errors: list[str] = []
    for path in sorted(SOURCE.rglob("*.py")):
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE_LENGTH:
                errors.append(
                    f"{relative}:{line_number}: line exceeds "
                    f"{MAX_LINE_LENGTH} characters"
                )
            if line.rstrip() != line:
                errors.append(
                    f"{relative}:{line_number}: trailing whitespace"
                )
            if "\t" in line:
                errors.append(f"{relative}:{line_number}: tab character")
        errors.extend(_docstring_errors(relative, text))

    if errors:
        print("\n".join(errors))
        return 1
    print("Google-style guardrail checks passed.")
    return 0


def _docstring_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    tree = ast.parse(text)
    if ast.get_docstring(tree) is None:
        errors.append(f"{path}: missing module docstring")
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            if node.name.startswith("_"):
                continue
            if ast.get_docstring(node) is None:
                errors.append(
                    f"{path}:{node.lineno}: public {node.name} lacks docstring"
                )
    return errors


if __name__ == "__main__":
    sys.exit(main())
