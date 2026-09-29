import os

files_to_include = [
    "README.md",
    "PROGRESS.md",
    "docs/ATTACK_WINDOWS.md",
    "evaluation/REPORT.md",
    "src/routes/README.md",
]

with open("SHORT_CONTEXT.md", "w", encoding="utf-8") as out:
    out.write("# SIH-2026 Project Context for Hackathon Q&A\n\n")
    out.write("This document contains the project overview, current progress, attack-window evidence, evaluation results, and frontend routing conventions.\n\n")
    
    for filepath in files_to_include:
        if os.path.exists(filepath):
            out.write(f"## {filepath}\n\n")
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    out.write(f.read())
            except Exception as e:
                out.write(f"[Error reading file: {e}]")
            out.write("\n\n---\n\n")
        else:
            out.write(f"## {filepath}\n[File not found]\n\n---\n\n")

print("Generated SHORT_CONTEXT.md successfully.")
