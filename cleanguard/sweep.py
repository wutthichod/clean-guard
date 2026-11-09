"""Read content without asking the model (C). UAT report issue 2.

UAT-04 and UAT-12 missed the same two private files: document (3).docx (a bank statement) and
notes.txt (a Thai ID). Content was only read if the 4B model chose the file among its 3 reads
per batch, and it did not choose them.

sweep_signals runs before TRIAGE and reads the first 1,500 characters of every text, PDF and
Word file under 2 MB, locally and without the model. Privacy signals then run on that text: a
checksum-valid Thai ID or card number, or a privacy keyword. Signals only raise sensitivity.

Text is kept, and passed to the model, only when it helps: for privacy hits, generic names
(scan_001.pdf, notes.txt) and drafts. It stays in memory (run.snippets) and is never logged:
the log line holds counts only, and state.json holds character counts, not text.
"""
from __future__ import annotations

from .evidence import is_draft_name, is_generic_name, usable_chars
from .safety import ensure_inside
from .signals import find_signals
from .snippets import SUPPORTED, extract_text


def sweep_signals(run, cfg) -> dict:
    cap = cfg.privacy.sweep_max_mb * 1024 * 1024
    read = hits = failed = 0
    for r in run.records.values():
        if r.protected or r.ext not in SUPPORTED or not 0 < r.size_bytes <= cap:
            continue
        try:
            text = extract_text(ensure_inside(run.root, r.abs_path), cfg.privacy.sweep_chars)
        except Exception:  # noqa: BLE001 - broken or locked files are expected; skip them
            failed += 1
            continue
        read += 1
        run.read_chars[r.file_id] = usable_chars(text)
        hit = bool(find_signals("", text))
        hits += hit
        if hit or is_generic_name(r.name) or is_draft_name(r.name):
            run.snippets[r.file_id] = text
    return {"read": read, "hits": hits, "failed": failed}


def name_duplicates(run) -> int:
    """Say which file a duplicate copies, by name, in reasons the model wrote, such as a copy
    of a passport scan (UAT-05). Rule-decided duplicates already name the original."""
    n = 0
    for f, d in run.decisions.items():
        r = run.records[f]
        if not r.dup_of or d.decided_by == "rule" or r.dup_of not in run.records:
            continue
        original = run.records[r.dup_of].rel_path
        if original not in d.reason:
            d.reason = f"{d.reason.rstrip().rstrip('.')}. Exact copy of {original}."
            n += 1
    return n
