#!/usr/bin/env python3"""
import json
import re
import sys
from pathlib import Path

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False


def extract_with_tree_sitter(source: str) -> dict:
    tree = parser.parse(bytes(source, "utf8"))
    root = tree.root_node
    functions = []
    classes = []
    imports = []

    def walk(node):
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                functions.append({
                    "name": name_node.text.decode(),
                    "params": params_node.text.decode() if params_node else "()",
                    "line": node.start_point[0] + 1
                })
        elif node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                classes.append({
                    "name": name_node.text.decode(),
                    "line": node.start_point[0] + 1
                })
        elif node.type in ("import_statement", "import_from_statement"):
            imports.append(node.text.decode())
        for child in node.children:
            walk(child)

    walk(root)
    return {"functions": functions, "classes": classes, "imports": imports}


def extract_simple(source: str) -> dict:
    """Fallback regex parser if tree-sitter is unavailable."""
    functions = []
    classes = []
    imports = []

    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("def "):
            match = re.match(r"def (\w+)\(([^)]*)\)", stripped)
            if match:
                functions.append({
                    "name": match.group(1),
                    "params": f"({match.group(2)})",
                    "line": i
                })
        elif stripped.startswith("class "):
            match = re.match(r"class (\w+)", stripped)
            if match:
                classes.append({"name": match.group(1), "line": i})
        elif stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(stripped)

    return {"functions": functions, "classes": classes, "imports": imports}


def build_repo_map(repo_path: Path, recursive: bool = False) -> dict:
    """
    Build a compressed map of all Python files in a repository.
    
    Args:
        repo_path: Path to the repository root
        recursive: If True, use rglob to find nested .py files.
                   If False, only scan top-level files.
    """
    repo_map = {}

    # Fix: use rglob for nested repos, glob for flat
    glob_fn = repo_path.rglob if recursive else repo_path.glob
    py_files = sorted(glob_fn("*.py"))

    for py_file in py_files:
        try:
            source = py_file.read_text()
        except Exception:
            continue

        if TREE_SITTER_AVAILABLE:
            extracted = extract_with_tree_sitter(source)
        else:
            extracted = extract_simple(source)

        # Use relative path as key so nested files are identifiable
        key = str(py_file.relative_to(repo_path)) if recursive else py_file.name

        repo_map[key] = {
            "lines": len(source.splitlines()),
            "imports": extracted["imports"],
            "classes": [f"{c['name']} (line {c['line']})" for c in extracted["classes"]],
            "functions": [f"{f['name']}{f['params']} (line {f['line']})" for f in extracted["functions"]],
        }

    return repo_map


def format_repo_map(repo_map: dict) -> str:
    lines = ["Repository structure:\n"]
    for filename, info in repo_map.items():
        lines.append("=" * 40)
        lines.append(f"File: {filename} ({info['lines']} lines)")
        if info["imports"]:
            lines.append(f"  Imports: {', '.join(info['imports'][:5])}")
        if info["classes"]:
            lines.append(f"  Classes: {', '.join(info['classes'])}")
        if info["functions"]:
            lines.append(f"  Functions: {', '.join(info['functions'])}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    repo_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    recursive = "--recursive" in sys.argv or "-r" in sys.argv
    repo_map = build_repo_map(repo_path, recursive=recursive)
    print(format_repo_map(repo_map))
    print("\nJSON:")
    print(json.dumps(repo_map, indent=2))
