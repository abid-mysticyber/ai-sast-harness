#!/usr/bin/env python

import json
import sys
import time
import requests
import argparse
from pathlib import Path

DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_GROUND_TRUTH = "../ground_truth.json"
DEFAULT_CONTEXT_WINDOW_SIZE = 2048

def main(argv=None):
    if not argv:
        argv = sys.argv

    parser = argparse.ArgumentParser(prog='scan')
    parser.add_argument('-m', '--model', dest='model', default=DEFAULT_MODEL)
    parser.add_argument('-g', '--ground-truth', dest='ground_truth', default=DEFAULT_GROUND_TRUTH)
    parser.add_argument('-c', '--context', type=int, dest='context_size', default=DEFAULT_CONTEXT_WINDOW_SIZE)
    parser.add_argument(dest='repository', nargs='?')

    args = parser.parse_args()
    if not args.model or not args.ground_truth:
        print("Usage: python3 scan.py <repo_path> <num_ctx>")
        print("Example: python3 scan.py ../apps/baseline 2048")
        return 1

    repo_path = Path(args.repository)
    ground_truth = json.loads(Path(args.ground_truth).read_text())

    combined = ""

    for py_file in sorted(repo_path.glob("*.py")):
        combined += f"\n=== BEGIN FILE: {py_file.name} ===\n"
        combined += py_file.read_text()
        combined += f"\n=== END FILE: {py_file.name} ===\n"

    prompt = f"""
    You are evaluating a small intentionally vulnerable Flask-style Python app.

    Before analyzing vulnerabilities, list every file name you received in files_seen.

    Your task:
    Find the single most important OWASP-style vulnerability in the code.

    Important rules:
    - Do not invent vulnerabilities.
    - Do not report logging or observability as command injection unless an OS command is actually executed.
    - Focus on authorization, authentication, injection, path traversal, deserialization, and sensitive data exposure.
    - Return JSON only.

    Expected JSON schema:
    {{
      "files_seen": [],
      "vulnerability_found": true,
      "vulnerability_type": "",
      "cwe": "",
      "file": "",
      "function": "",
      "reason": "",
      "confidence": 0
    }}

    Code:
    {combined}
    """

    start = time.time()
    request = {
        "model": args.model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_ctx": args.context_size
        }
    }

    response = requests.post(
        "http://localhost:11434/api/generate",
        json=request
    )

    duration = time.time() - start
    data = response.json()

    #model_response = json.loads(data.get('response').replace('```json`', '').replace('```', ''))
    output = {
        'model': args.model,
        'context_size': args.context_size,
        'repository': args.repository,
        'response': data.get('response'),
        'metrics': {
            'duration': round(duration, 2),
            'prompt_eval_count': data.get('prompt_eval_count'),
            'eval_count': data.get('eval_count'),
            'context_window_exceeded': data.get('prompt_eval_count', 0) >= args.context_size
        },
        'ground_truth': ground_truth
    }

    print(json.dumps(output, indent=2))

    return 0

if __name__ == '__main__':
    sys.exit(main())
