import requests
from pathlib import Path

repo_path = Path("../apps/baseline")

combined = ""

for py_file in repo_path.glob("*.py"):
    combined += f"\n# FILE: {py_file.name}\n"
    combined += py_file.read_text()

prompt = f'''
Analyze this Flask codebase for OWASP vulnerabilities.

Return:
- vulnerability_found
- cwe
- file
- reason

Code:
{combined}
'''

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "qwen2.5-coder:7b",
        "prompt": prompt,
        "stream": False
    }
)

print(response.json()["response"])
