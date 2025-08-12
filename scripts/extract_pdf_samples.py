"""Extract sample transaction lines from a PDF statement (local-only).

Usage:
  python extract_pdf_samples.py --pdf /path/to/statement.pdf \
      --max-lines 60 --anonymize --output sample_lines.txt

Features:
- Local parsing only (privacy preserved)
- Simple heuristics to collect lines that look like transactions
  (date & amount)
- Optional anonymization of merchant text (replace alpha sequences with XXXX)
- Outputs to stdout or a file

Limitations:
- Not full transaction parsing (for diagnostics only)
- No network usage; relies solely on pdfplumber

Security Rationale:
- Reads only specified file path
- No external calls; keeps sensitive data local
- Optional anonymization reduces exposure when sharing samples
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List

import pdfplumber

DATE_PATTERN = re.compile(r"\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b")
# Capture money tokens like 1,234.56 or (123.45) or -123.45
AMOUNT_PATTERN = re.compile(
    (
        r"(?<![A-Za-z0-9])"  # Not preceded by word/number
        r"(?:\(?"  # Optional opening parenthesis
        r"\$?"  # Optional dollar sign
        r"\d{1,3}(?:,\d{3})*"  # Thousands groups
        r"(?:\.\d{2})?"  # Optional cents
        r"\)?)"  # Optional closing parenthesis
        r"(?![A-Za-z0-9])"  # Not followed by word/number
    )
)
ALPHA_GROUP_PATTERN = re.compile(r"[A-Za-z]{4,}")


def extract_candidate_lines(pdf_path: Path, max_lines: int) -> List[str]:
    lines: List[str] = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                # Must contain a date-like token
                if not DATE_PATTERN.search(line):
                    continue
                # Should contain at least one numeric token (amount or number)
                if not re.search(r"\d", line):
                    continue
                # Prefer lines with an amount-looking pattern to surface real transactions
                if AMOUNT_PATTERN.search(line):
                    lines.append(line)
                else:
                    # Fallback: if it has two or more numbers (date + something else)
                    if len(re.findall(r"\d+", line)) >= 2:
                        lines.append(line)
                if len(lines) >= max_lines:
                    return lines
    return lines


def anonymize_line(line: str) -> str:
    # Replace sequences of 4+ letters (likely merchant names/words) with XXXX
    # Preserves at most 8 X length for readability when shared
    return ALPHA_GROUP_PATTERN.sub(lambda m: "X" * min(len(m.group()), 8), line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("Extract sample transaction lines from a PDF statement")
    )
    parser.add_argument("--pdf", required=True, type=Path, help="Path to PDF statement")
    parser.add_argument(
        "--max-lines",
        type=int,
        default=60,
        help="Maximum candidate lines to collect",
    )
    parser.add_argument("--output", type=Path, help="Optional output file path")
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize merchant / description text",
    )
    parser.add_argument(
        "--filter",
        type=str,
        help=(
            "Optional substring filter; keep only lines containing this text "
            "(case-insensitive)"
        ),
    )
    args = parser.parse_args()

    pdf_path: Path = args.pdf
    if not pdf_path.exists() or not pdf_path.is_file():
        print(f"Error: PDF not found: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    try:
        lines = extract_candidate_lines(pdf_path, args.max_lines)
    except Exception as e:
        print(f"Failed to read PDF: {e}", file=sys.stderr)
        sys.exit(2)

    if args.filter:
        flt = args.filter.lower()
        lines = [ln for ln in lines if flt in ln.lower()]

    if args.anonymize:
        lines = [anonymize_line(ln) for ln in lines]

    # De-duplicate while preserving order
    seen = set()
    unique_lines: List[str] = []
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            unique_lines.append(ln)

    output_text = "\n".join(unique_lines)

    if args.output:
        try:
            args.output.write_text(output_text, encoding="utf-8")
            print(f"Wrote {len(unique_lines)} lines to {args.output}")
        except Exception as e:
            print(f"Failed to write output file: {e}", file=sys.stderr)
            sys.exit(3)
    else:
        print(output_text)


if __name__ == "__main__":  # pragma: no cover
    main()
