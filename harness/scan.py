import json
import sys
import time
import requests
from pathlib import Path

MODEL = "qwen2.5-coder:7b"
GROUND_TRUTH = "../ground_truth.json"

if len(sys.argv) != 3:
    print("Usage: python3 scan.py <repo_path> <num_ctx>")
    print("Example: python3 scan.py ../apps/baseline 2048")
    sys.exit(1)

REPO_VARIANT = sys.argv[1]
NUM_CTX = int(sys.argv[2])

repo_path = Path(REPO_VARIANT)
ground_truth = json.loads(Path(GROUND_TRUTH).read_text())

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

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_ctx": NUM_CTX
        }
    }
)

duration = time.time() - start
data = response.json()

print("REPO_VARIANT:", REPO_VARIANT)
print("NUM_CTX:", NUM_CTX)

print("\nMODEL RESPONSE:")
print(data["response"])

print("\nMETRICS:")
print("duration_seconds:", round(duration, 2))
print("prompt_eval_count:", data.get("prompt_eval_count"))
print("eval_count:", data.get("eval_count"))

print("\nGROUND TRUTH:")
print(json.dumps(ground_truth, indent=2))