"""
SWE-bench evaluation harness for AI Agent OS.
Runs the full SWE-bench Verified dataset against our agent.
"""
import json
import subprocess
import sys
import os
from pathlib import Path
from datasets import load_dataset

def run_agent(issue_text, repo_path):
    """Run our agent CLI on a SWE-bench task."""
    prompt = f"""You are fixing a bug in a Python repository at {repo_path}.

Here is the GitHub issue:
{issue_text}

Instructions:
1. Read the relevant source files to understand the codebase
2. Identify the root cause of the bug
3. Write a fix (modify the necessary files)
4. Make sure your fix doesn't break existing functionality

Use the available tools (read_file, write_file, run_command, list_directory) to explore and fix the code.
Only modify files that need to be changed. Be precise."""

    env = os.environ.copy()
    result = subprocess.run(
        ["cargo", "run", "-q", "--package", "agent-cli", "--", "-c", prompt],
        capture_output=True, text=True, timeout=300,
        cwd="/home/surya/AI Agent OS", env=env
    )
    return result.stdout

def generate_patch(repo_path, original_commit):
    """Generate a git diff patch from the agent's changes."""
    result = subprocess.run(
        ["git", "diff", original_commit],
        capture_output=True, text=True, cwd=repo_path
    )
    return result.stdout

def main():
    print("=" * 60)
    print("  SWE-bench Full Evaluation — AI Agent OS")
    print("=" * 60)

    # Load dataset
    print("\nLoading SWE-bench Verified dataset...")
    dataset = load_dataset("princeton-nlp/SWE-bench_Verified", split="test")
    print(f"Total tasks: {len(dataset)}")

    # For the first run, let's do a subset to validate the pipeline works
    max_tasks = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"Running first {max_tasks} tasks...\n")

    results = []
    for i, task in enumerate(dataset):
        if i >= max_tasks:
            break

        instance_id = task["instance_id"]
        repo = task["repo"]
        issue = task["problem_statement"]

        print(f"[{i+1}/{max_tasks}] {instance_id}")
        print(f"  Repo: {repo}")
        print(f"  Issue: {issue[:80]}...")

        try:
            output = run_agent(issue, f"/tmp/swe_repos/{repo}")
            results.append({
                "instance_id": instance_id,
                "model_name_or_path": "ai-agent-os-gpt5.4",
                "model_patch": output[:5000] if output else "",
                "status": "completed"
            })
            print(f"  ✓ Agent responded ({len(output)} chars)")
        except subprocess.TimeoutExpired:
            results.append({"instance_id": instance_id, "status": "timeout"})
            print(f"  ✗ Timeout")
        except Exception as e:
            results.append({"instance_id": instance_id, "status": f"error: {e}"})
            print(f"  ✗ Error: {e}")

    # Save results
    output_path = "benchmarks/swebench_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    completed = sum(1 for r in results if r["status"] == "completed")
    print(f"\n{'=' * 60}")
    print(f"  Results: {completed}/{max_tasks} completed")
    print(f"  Saved to: {output_path}")
    print(f"{'=' * 60}")

if __name__ == "__main__":
    main()
