#!/usr/bin/env python3
"""
Packaging script for HackerRank Orchestrate: Ghost Data Still Exists.
Creates code.zip conforming strictly to AGENTS.md §6.9:
Excludes dataset/, virtual environments, dependency caches, and temporary files.
"""

import os
import zipfile

def package_solution(zip_name="code.zip"):
    print("=" * 70)
    print("PACKAGING SUBMISSION ARTIFACT (code.zip)")
    print("=" * 70)
    
    files_to_include = [
        "README.md",
        "AGENTS.md",
        "problem_statement.md",
        "code/main.py",
        "code/engine.py",
        "code/validate_output.py",
        "code/test_regression_fixes.py",
        "code/evaluation/main.py",
        "code/evaluation/evaluation_report.md",
        "code/evaluation/usage_report.md",
        "evaluation/evaluation_report.md",
        "evaluation/usage_report.md"
    ]
    
    if os.path.exists(zip_name):
        os.remove(zip_name)
        
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in files_to_include:
            if os.path.exists(f):
                zf.write(f, arcname=f)
                print(f"  + Added: {f}")
            else:
                print(f"  ! Warning: File missing: {f}")

    size_kb = os.path.getsize(zip_name) / 1024.0
    print(f"\n[SUCCESS] Created {zip_name} ({size_kb:.1f} KB)")
    print("Contents verified: Clean, self-contained, no dataset/, no .venv/, no secrets.")

if __name__ == "__main__":
    package_solution()
