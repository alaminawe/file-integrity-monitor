import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def scan_directory(directory: Path) -> dict:
    results = {}
    for file in directory.rglob("*"):
        if file.is_file():
            stat = file.stat()
            results[str(file)] = {
                "sha256": sha256_file(file),
                "size_bytes": stat.st_size,
                "mtime": stat.st_mtime,
            }
    return results

def save_baseline(files_data: dict, output_file: Path) -> None:
    baseline = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files_data,
    }
    output_file.write_text(json.dumps(baseline, indent=2))

def load_baseline(baseline_file: Path) -> dict:
    if not baseline_file.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")
    data = json.loads(baseline_file.read_text())
    return data.get("files", {})

def compare_states(baseline_files: dict, current_files: dict) -> dict:
    baseline_paths = set(baseline_files.keys())
    current_paths = set(current_files.keys())

    created = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)

    modified = []
    for path in sorted(current_paths & baseline_paths):
        if current_files[path]["sha256"] != baseline_files[path]["sha256"]:
            modified.append(path)

    return {"created": created, "deleted": deleted, "modified": modified}

def print_report(changes: dict) -> None:
    created = changes["created"]
    deleted = changes["deleted"]
    modified = changes["modified"]

    print("\n=== File Integrity Monitor Report ===")
    print(f"Created : {len(created)}")
    print(f"Modified: {len(modified)}")
    print(f"Deleted : {len(deleted)}\n")

    if created:
        print("[CREATED]")
        for p in created:
            print(f"  + {p}")
        print()

    if modified:
        print("[MODIFIED]")
        for p in modified:
            print(f"  * {p}")
        print()

    if deleted:
        print("[DELETED]")
        for p in deleted:
            print(f"  - {p}")
        print()

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor (Phase 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_base = sub.add_parser("baseline", help="Create a baseline.json snapshot")
    p_base.add_argument("--path", default="test_dir", help="Directory to baseline")
    p_base.add_argument("--out", default="baseline.json", help="Baseline output file")

    p_scan = sub.add_parser("scan", help="Scan and compare against baseline.json")
    p_scan.add_argument("--path", default="test_dir", help="Directory to scan")
    p_scan.add_argument("--baseline", default="baseline.json", help="Baseline file to compare against")

    args = parser.parse_args()

    target_dir = Path(args.path)

    if not target_dir.exists():
        print(f"Directory not found: {target_dir}")
        return

    if args.command == "baseline":
        files_data = scan_directory(target_dir)
        save_baseline(files_data, Path(args.out))
        print(f"Baseline saved to {args.out} ({len(files_data)} files).")

    elif args.command == "scan":
        baseline_files = load_baseline(Path(args.baseline))
        current_files = scan_directory(target_dir)
        changes = compare_states(baseline_files, current_files)
        print_report(changes)

if __name__ == "__main__":
    main()
