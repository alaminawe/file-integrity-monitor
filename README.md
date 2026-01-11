# File Integrity Monitor (FIM)

A Python-based defensive security tool that baselines a directory and detects file integrity changes using SHA-256 hashing.

## What it does
- Creates a baseline snapshot of files in a directory
- Detects and reports:
  - Created files
  - Modified files (hash mismatch)
  - Deleted files
- Tracks basic file metadata (size and last modified time)
- Uses UTC timestamps for integrity records

## Why this matters
File Integrity Monitoring is a core defensive security control used to detect unauthorized system changes, malware activity, and configuration drift.

## How to use

Create a baseline:
python fim.py baseline --path test_dir --out baseline.json

 Scan and compare against baseline:
python fim.py scan --path test_dir --baseline baseline.json
