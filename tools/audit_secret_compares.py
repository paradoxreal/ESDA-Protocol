#!/usr/bin/env python3
"""S2 audit: flag `==` / `!=` comparisons that touch secret-looking values.

Secret material (shares, MACs, digests compared against attacker input, keys) must be
compared with hmac.compare_digest. This scan is a tripwire, not a proof: it flags any
==/!= whose operands mention a secret-looking name, and fails unless the comparison carries an
inline `# ct-ok: <reason>` marker saying why it is not a secret-vs-input timing risk. Usage: python3 tools/audit_secret_compares.py [file]
"""
import ast
import re
import sys

SECRET = re.compile(r"secret|share|digest|mac|tag|token|password|priv|seed|\bd\b|dp|dq", re.I)

def scan(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            text = ast.get_source_segment(src, node) or ""
            if SECRET.search(text):
                lines = src.splitlines()[node.lineno - 1:node.end_lineno]
                note = next((l.split("# ct-ok:", 1)[1].strip() for l in lines if "# ct-ok:" in l), None)
                hits.append((node.lineno, " ".join(text.split()), note))
    return hits


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "esda_protocol.py"
    bad = []
    for line, text, reason in scan(path):
        print(f"{path}:{line}: {'reviewed' if reason else 'UNREVIEWED'}: {text}" + (f"  — {reason}" if reason else ""))
        if not reason:
            bad.append(line)
    print(f"\n{len(bad)} unreviewed secret comparison(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
