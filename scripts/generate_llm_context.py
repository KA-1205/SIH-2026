import os

files_to_scan = [
    ".md", ".py", ".sh", "Makefile", ".js", ".css", ".html"
]

skip_dirs = [
    ".git", ".venv", "graphify-out", "__pycache__", 
    "data", "datasets", "models/artifacts", "replay/slices"
]

skip_files = [
    "demo_out.log", "demo_out2.log", "LLM_CONTEXT.md"
]

with open("LLM_CONTEXT.md", "w", encoding="utf-8") as out:
    out.write("# Project Context: Unidirectional Network Threat Detection (SIH26145)\n\n")
    out.write("This file contains the entire codebase and documentation for context.\n\n")
    
    for root, dirs, files in os.walk("."):
        # Remove skipped directories in-place so os.walk doesn't traverse them
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in sorted(files):
            # Skip if it doesn't match our allowed extensions or is explicitly excluded
            if not any(file.endswith(ext) or file == ext for ext in files_to_scan):
                continue
            if file.endswith(".original") or file in skip_files:
                continue
                
            path = os.path.join(root, file)
            out.write(f"## {path}\n```\n")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    out.write(f.read())
            except Exception as e:
                out.write(f"[Error reading file: {e}]")
            out.write("\n```\n\n")

print("Generated LLM_CONTEXT.md successfully.")
