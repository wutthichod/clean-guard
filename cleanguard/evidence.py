"""Evidence for labels and reasons (C). UAT report issues 1 and 4.

UAT-10, 11 and 12 failed because missing evidence was treated as evidence: an image-only PDF,
a one-line note and an only-copy backup were marked deletable on their name and age. So a
"deletable" label now needs a positive reason that code can check:

    | Evidence                         | Check                                         |
    | exact duplicate                  | dup_of is set (same size and SHA-256)         |
    | junk name                        | matches the OS profile                        |
    | unfinished download              | partial extension, older than the minimum age |
    | installer                        | .exe .msi .dmg .pkg ... , no keep word in name |
    | draft replaced by a final        | text was read, and a final of the same name   |
    |                                  | sits in the same folder                       |

Anything else the model calls deletable becomes "review". Age alone is never evidence, and
neither is a file the model could not see inside. Labels only move towards "review", so the
rule can cost some reclaimable space but never a needed file.

ground_reasons does the same for words: a reason may only claim what was shown to the model.
"""
from __future__ import annotations

import re

MIN_TEXT_CHARS = 30      # less than this is "near empty": no evidence of anything
NO_TEXT = "[no extractable text"

INSTALLER_EXT = {".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage"}
KEEP_WORDS = ("backup", "back_up", "back-up", "archive", "only_copy", "only copy", "only-copy",
              "onlycopy", "master_copy", "master copy", "สำรอง", "ต้นฉบับ")
DRAFT_WORDS = ("ฉบับร่าง", "draft", "ร่าง")
FINAL_WORDS = ("ฉบับสมบูรณ์", "ฉบับสุดท้าย", "ฉบับจริง", "final")

GENERIC_STEM = re.compile(
    r"^(scan|scanned|document|doc|file|notes?|untitled|new[ _-]?document|new[ _-]?file|data|"
    r"misc|temp|tmp|stuff|copy|download|img|image|photo|pic|ไฟล์|เอกสาร|สแกน)?"
    r"[ _-]*\(?\d*\)?$", re.I)

# Claims about content. Only allowed when the model was shown the text.
CONTENT_CLAIM = re.compile(r"\b(empty|blank|minimal|contains?|holds?|extracted|unpacked|"
                           r"short note|no content|no text|little content)\b", re.I)
EMPTY_CLAIM = re.compile(r"\b(empty|blank|no content|no text|minimal|little content)\b", re.I)
NO_FINAL_CLAIM = re.compile(r"\bno final\b|\bfinal version (is )?(missing|absent|not)\b", re.I)


def usable_chars(text: str) -> int:
    """Characters of real text; the placeholder for an image-only PDF counts as none."""
    text = (text or "").strip()
    return 0 if text.startswith(NO_TEXT) else len(text)


def is_generic_name(name: str) -> bool:
    """scan_001.pdf, document (3).docx, notes.txt, untitled.pdf: says nothing about the file."""
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return bool(stem.strip()) and GENERIC_STEM.match(stem.strip()) is not None


def is_draft_name(name: str) -> bool:
    n = name.lower()
    return any(w in n for w in DRAFT_WORDS)


def has_keep_word(name: str) -> bool:
    n = name.lower()
    return any(w in n for w in KEEP_WORDS)


def _base(name: str) -> str:
    """essay_draft2.docx and essay_final.docx both give "essay"."""
    stem = name.rsplit(".", 1)[0].lower()
    for w in DRAFT_WORDS + FINAL_WORDS:
        stem = stem.replace(w, "")
    return re.sub(r"[\W_\d]+", "", stem)


def _final_exists(r, run) -> bool:
    folder, base = r.rel_path.rsplit("/", 1)[0] if "/" in r.rel_path else "", _base(r.name)
    if not base:
        return False
    for o in run.records.values():
        ofolder = o.rel_path.rsplit("/", 1)[0] if "/" in o.rel_path else ""
        if o.file_id != r.file_id and ofolder == folder and _base(o.name) == base \
                and any(w in o.name.lower() for w in FINAL_WORDS):
            return True
    return False


def deletable_evidence(r, run, cfg) -> str | None:
    """The positive reason this file may be labelled deletable, or None if there is none."""
    if r.dup_of:
        return "exact duplicate"
    if run.profile.is_junk_name(r.name):
        return "junk name"
    if r.ext in run.profile.partial_download_ext and \
            r.modified_days >= cfg.scan.partial_download_min_age_days:
        return "unfinished download"
    if has_keep_word(r.name):
        return None                         # a backup or only copy is the user's call
    if r.ext in INSTALLER_EXT:
        return "installer"
    if is_draft_name(r.name) and run.read_chars.get(r.file_id, 0) >= MIN_TEXT_CHARS \
            and _final_exists(r, run):
        return "draft replaced by a final version"
    return None


def apply_evidence(d, r, run, cfg, log) -> bool:
    """Turn a deletable label with no evidence into review. Per file, so one doubtful verdict
    does not throw away the rest of the batch or spend another model call on it."""
    if d.label != "deletable" or deletable_evidence(r, run, cfg) is not None:
        return False
    d.label, d.decided_by = "review", "evidence"
    d.reason = ("Its name suggests a backup or only copy, so check it before removing it."
                if has_keep_word(r.name) else
                "Nothing shows this file is unneeded: it is not an installer, a duplicate or an "
                "unfinished download. Check it yourself.")
    log.write("evidence_downgrade", run_id=run.run_id, file_id=d.file_id)   # id only, no name
    return True


def ground_reasons(run) -> int:
    """A model's reason may only claim what the model saw. Rule reasons are facts already."""
    changed = 0
    shown = set(run.shown)
    for f, d in run.decisions.items():
        if d.decided_by not in ("llm_fast", "llm_reasoning"):
            continue
        before, r = d.reason, run.records[f]
        if is_draft_name(r.name) and _final_exists(r, run) and NO_FINAL_CLAIM.search(d.reason):
            d.reason = "A draft; a final version with the same name is in this folder."
        elif f in shown and "not opened" in d.reason.lower():      # the model copied the phrase
            d.reason = "Judged from its name, type and the start of its text."
        if f not in shown:
            if CONTENT_CLAIM.search(d.reason):
                d.reason = "Judged from its name, type and age only."
            if "not opened" not in d.reason.lower():
                d.reason = f"{d.reason.rstrip().rstrip('.')}. (File not opened.)"
        elif run.read_chars.get(f, 0) >= MIN_TEXT_CHARS and EMPTY_CLAIM.search(d.reason):
            d.reason = "Judged from its name, type and the start of its text."
        changed += d.reason != before
    return changed
