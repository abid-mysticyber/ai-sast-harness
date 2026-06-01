#!/usr/bin/env python3

import json
import sys
import time
import argparse
import requests
from pathlib import Path
from repomap import build_repo_map, format_repo_map

DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_GROUND_TRUTH = "../ground_truth.json"
DEFAULT_CONTEXT = 8192
OLLAMA_URL = "http://localhost:11434/api/generate"


def ollama_generate(model, prompt, num_ctx, temperature=0):
    response = requests.post(OLLAMA_URL, json={
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": num_ctx}
    })
    data = response.json()
    return data.get("response", ""), data.get("prompt_eval_count", 0), data.get("eval_count", 0)


def stage1_file_selection(model, repo_map_text, num_ctx):
    """Ask model which files to prioritize for security review."""
    prompt = f"""You are a security code reviewer. You have been given a map of a repository.
Your task is to decide which files to inspect for security vulnerabilities.

{repo_map_text}

Based on this repository map, list the files you want to inspect for security vulnerabilities.
Rank them by priority with the most security-relevant files first.
Return ONLY a JSON array of filenames in priority order.
Example: ["app.py", "auth.py", "db.py"]
Return JSON only, no explanation."""

    response, prompt_tokens, eval_tokens = ollama_generate(model, prompt, num_ctx)
    
    import re
    cleaned = re.sub(r'```json|```', '', response).strip()
    try:
        selected_files = json.loads(cleaned)
        if not isinstance(selected_files, list):
            selected_files = list(repo_map_text.keys())
    except Exception:
        selected_files = []
    
    return selected_files, prompt_tokens, eval_tokens, response


def stage2_vulnerability_scan(model, repo_path, selected_files, num_ctx):
    """Feed selected files and scan for vulnerabilities."""
    combined = ""
    files_loaded = []
    
    for filename in selected_files:
        filepath = repo_path / filename
        if filepath.exists():
            combined += f"\n=== BEGIN FILE: {filename} ===\n"
            combined += filepath.read_text()
            combined += f"\n=== END FILE: {filename} ===\n"
            files_loaded.append(filename)
    
    prompt = f"""You are a security code reviewer analyzing the following files for vulnerabilities.
Find the single most important OWASP-style security vulnerability.

Important rules:
- Focus on authorization, authentication, injection, deserialization, sensitive data exposure.
- Do not invent vulnerabilities.
- Return ONLY JSON matching this schema:

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

Code to analyze:
{combined}"""

    response, prompt_tokens, eval_tokens = ollama_generate(model, prompt, num_ctx)
    return response, prompt_tokens, eval_tokens, files_loaded


def main():
    parser = argparse.ArgumentParser(prog='scan_retrieval')
    parser.add_argument('-m', '--model', default=DEFAULT_MODEL)
    parser.add_argument('-c', '--context', type=int, default=DEFAULT_CONTEXT)
    parser.add_argument('-g', '--ground-truth', default=DEFAULT_GROUND_TRUTH)
    parser.add_argument('repository')
    args = parser.parse_args()

    repo_path = Path(args.repository)
    ground_truth = json.loads(Path(args.ground_truth).read_text())

    # Build repo map
    repo_map = build_repo_map(repo_path)
    repo_map_text = format_repo_map(repo_map)
    all_files = list(repo_map.keys())

    start = time.time()

    # Stage 1 — file selection
    selected_files, s1_prompt_tokens, s1_eval_tokens, s1_raw = stage1_file_selection(
        args.model, repo_map_text, args.context
    )

    # Stage 2 — vulnerability scan on selected files
    s2_response, s2_prompt_tokens, s2_eval_tokens, files_loaded = stage2_vulnerability_scan(
        args.model, repo_path, selected_files if selected_files else all_files, args.context
    )

    duration = time.time() - start

    # Check if vulnerable file was selected
    vuln_file = ground_truth.get("file", "app.py")
    vuln_file_selected = vuln_file in selected_files
    vuln_file_rank = selected_files.index(vuln_file) + 1 if vuln_file in selected_files else -1

    output = {
        "model": args.model,
        "context_size": args.context,
        "repository": args.repository,
        "stage1": {
            "selected_files": selected_files,
            "raw_response": s1_raw,
            "prompt_tokens": s1_prompt_tokens,
            "eval_tokens": s1_eval_tokens,
        },
        "stage2": {
            "files_loaded": files_loaded,
            "response": s2_response,
            "prompt_tokens": s2_prompt_tokens,
            "eval_tokens": s2_eval_tokens,
        },
        "retrieval_metrics": {
            "vuln_file_selected": vuln_file_selected,
            "vuln_file_rank": vuln_file_rank,
            "total_files_in_repo": len(all_files),
            "files_selected": len(selected_files),
            "poisoned_files_selected": [
                f for f in selected_files
                if f not in [vuln_file, "db.py"]
            ],
        },
        "metrics": {
            "duration": round(duration, 2),
            "total_prompt_tokens": s1_prompt_tokens + s2_prompt_tokens,
            "total_eval_tokens": s1_eval_tokens + s2_eval_tokens,
        },
        "ground_truth": ground_truth
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    sys.exit(main())
