"""CLI (M18, D).

    python -m cleanguard ui                   # local web app: scan, files, quarantine, chat
    python -m cleanguard clean ~/Downloads    # guided: scan, open the report, approve, show undo
    python -m cleanguard scan ~/Downloads [--config C4] [--dry-run]
    python -m cleanguard approve <run_id>
    python -m cleanguard restore <batch_id>
    python -m cleanguard runs                 # list runs and quarantine batches
    python -m cleanguard resume <run_id>      # continue a FAILED run (e.g. Ollama was down)
"""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

from harness import Harness, execute, load_config

from . import quarantine
from .platform import load_profile
from .report import console_summary, groups, mb
from .safety import GATE
from .settings import DEFAULT_SETTINGS, load_settings
from .state_machine import S, CleanGuardRun, load_run, new_run, run_dir

__all__ = ["main", "approve", "parse_selection", "quarantine_selection", "restore_flow",
           "selectable_groups", "offline_line"]


def offline_line(base_url: str) -> str:
    """Proof for the user on every run (UAT report item 6): says where data really goes."""
    host = urlparse(base_url).hostname
    if host in ("localhost", "127.0.0.1", "::1"):
        return f"Offline: file names and text stay on this computer (local model at {base_url})."
    return f"WARNING: the model is at {host}, not this computer. File names and text go there."


class Cancelled(Exception):
    pass


def parse_selection(text: str, n: int) -> list[int]:
    """'all', 'none', '' or numbers like '1,3,7-12' -> sorted 1-based indexes within 1..n."""
    t = text.strip().lower()
    if t in ("", "none"):
        return []
    if t == "all":
        return list(range(1, n + 1))
    out = set()
    for part in t.replace(" ", "").split(","):
        if not part:
            continue
        a, sep, b = part.partition("-")
        lo, hi = (int(a), int(b)) if sep else (int(a), int(a))
        if lo > hi or lo < 1 or hi > n:
            raise ValueError(f"{part} is outside 1-{n}")
        out.update(range(lo, hi + 1))
    return sorted(out)


def _ask(ask, prompt: str) -> str:
    try:
        return ask(prompt)
    except (EOFError, KeyboardInterrupt):
        raise Cancelled from None


def _pick(ask, say, prompt: str, numbered: dict[int, object]) -> list:
    while True:
        text = _ask(ask, prompt)
        try:
            idx = parse_selection(text, max(numbered, default=0))
        except ValueError as e:
            say(f"  {e}. Try again, or press Ctrl+C to stop.")
            continue
        bad = [i for i in idx if i not in numbered]
        if bad and text.strip().lower() != "all":
            say(f"  numbers {bad} cannot be chosen here. Try again.")
            continue
        return [numbered[i] for i in idx if i in numbered]


def approve(h, run, cfg, ask=input, say=print) -> dict | None:
    """Section 17.3. Returns the quarantine result, or None when nothing moved."""
    runner = CleanGuardRun(h, run, cfg)
    if S(run.state) != S.APPROVE:
        raise RuntimeError(f"run {run.run_id} is in state {run.state}, not APPROVE")
    dele, revw, sens = selectable_groups(run)
    sens_chosen = []
    try:
        if not dele and not revw and not sens:
            say("Nothing to approve.")
            raise Cancelled
        chosen = []
        if dele:
            say(f"Deletable files ({len(dele)}):")
            for i, (r, d) in dele.items():
                say(f"  {i:>4}. {mb(r.size_bytes):>10}  {r.rel_path}  - {d.reason}")
            chosen = _pick(ask, say, "Move which files? (all / none / e.g. 1,3,7-12): ", dele)

        if revw:
            say(f"Review files ({len(revw)}), not selected unless you add them:")
            for i, (r, d) in revw.items():
                say(f"  {i:>4}. {mb(r.size_bytes):>10}  {r.rel_path}  - {d.reason}")
            chosen += _pick(ask, say, "Add review files by number (Enter for none): ", revw)

        if sens:
            say(f"Sensitive files ({len(sens)}): probably personal documents. They stay where they "
                "are unless you add them:")
            for i, (r, d) in sens.items():
                say(f"  {i:>4}. {mb(r.size_bytes):>10}  {r.rel_path} [SENSITIVE: {d.sensitive_type}, "
                    f"marked {d.label}]  - {d.reason}")
            extra = _pick(ask, say, "Add sensitive files by number (Enter for none): ", sens)
            if extra:
                say(f"WARNING: {len(extra)} file(s) may hold personal data (ID, bank, tax or similar):")
                for r, d in extra:
                    say(f"    {r.rel_path} ({d.sensitive_type})")
                say("Move them only if you have another copy you trust. They can be restored "
                    "from the quarantine.")
                if _ask(ask, "Type SENSITIVE to include them, anything else to leave them: ") \
                        .strip() == "SENSITIVE":
                    chosen += extra
                    sens_chosen = [r.file_id for r, _ in extra]
                else:
                    say("Sensitive files left where they are.")

        if not chosen:
            say("Nothing selected. Nothing was moved.")
            raise Cancelled
        total = sum(r.size_bytes for r, _ in chosen)
        say(f"{len(chosen)} files, {mb(total)}, will move to {run.profile.quarantine_dir}")
        say("They can be restored at any time. Nothing is deleted permanently.")
        if _ask(ask, "Type MOVE to continue: ").strip() != "MOVE":
            say("Cancelled. Nothing was moved.")
            raise Cancelled
    except Cancelled:
        runner.go(S.DONE)
        return None

    return quarantine_selection(h, run, cfg, [r.file_id for r, _ in chosen], sens_chosen,
                                say).get("result")


def selectable_groups(run) -> tuple[dict, dict, dict]:
    """What the user may choose to move, numbered as in the report: deletable, review, and
    sensitive files whatever their label (UAT-05). Sensitive files are never preselected."""
    g = groups(run)
    num = dict(enumerate(g["deletable"] + g["review"] + g["sensitive"], 1))
    return ({i: x for i, x in num.items() if x[1].label == "deletable" and not x[1].sensitive},
            {i: x for i, x in num.items() if x[1].label == "review" and not x[1].sensitive},
            {i: x for i, x in num.items() if x[1].sensitive and not x[0].protected})


def quarantine_selection(h, run, cfg, ids: list[str], sensitive_ids=(), say=print) -> dict:
    """Move files the user has already confirmed. Every move, from the CLI or the web app, goes
    through here, and this is the only place an approval token is issued. Callers must have the
    user's typed MOVE (and SENSITIVE for sensitive files); no model reaches this function."""
    runner = CleanGuardRun(h, run, cfg)
    if S(run.state) != S.APPROVE:
        raise RuntimeError(f"run {run.run_id} is in state {run.state}, not APPROVE")
    token = GATE.issue(run.run_id, ids, cfg.approval.token_ttl_minutes)
    runner.go(S.QUARANTINE)
    res = execute({"function": {"name": "quarantine_files",
                                "arguments": {"file_ids": ids, "approval_token": token}}},
                  allowed={"read", "write"}, logger=h.log, run_id=run.run_id)
    if res["ok"]:
        q = res["result"]
        run.approved, run.batch_id = ids, q["batch_id"]
        run.quarantine_batches.append(q["batch_id"])
        run.sensitive_confirmed = sorted(set(sensitive_ids) & set(q["moved"]))
        h.log.write("quarantine_batch", run_id=run.run_id, batch_id=q["batch_id"],
                    files=len(q["moved"]), bytes=q["bytes"], skipped=len(q["skipped"]),
                    sensitive_confirmed=len(run.sensitive_confirmed), status=q["status"])
        if q["status"] == "rolled_back":
            say(f"An error occurred ({q.get('error')}); every file was put back. Nothing moved.")
        else:
            say(f"Moved {len(q['moved'])} files ({mb(q['bytes'])}) to batch {q['batch_id']}.")
            for s in q["skipped"]:
                r = run.records[s["file_id"]]
                say(f"  NOT moved: {r.rel_path} - {skip_reason(s['status'])}. It is still in its folder.")
            if any(s["status"] == "changed_since_scan" for s in q["skipped"]):
                say("  Scan the folder again if you still want to clean up a changed file.")
            say(f"Undo with: python -m cleanguard restore {q['batch_id']}")
    else:
        say(f"Quarantine refused: {res['error']}")
    runner.go(S.DONE)
    return res


def skip_reason(status: str) -> str:
    return ("it changed after the scan (edited, replaced or removed)"
            if status == "changed_since_scan" else "another app has it open")


def restore_flow(h, cfg, batch_id: str, qdir=None) -> dict:
    """Move a quarantine batch back. Shared by the CLI and the web app."""
    qdir = Path(qdir or load_profile().quarantine_dir)
    run_id = _find_batch_run(batch_id, qdir)
    runner = None
    if run_id and (Path(cfg.paths.runs_dir) / run_id / "state.json").exists():
        run = load_run(run_id, cfg)
        runner = CleanGuardRun(h, run, cfg)
        if run.state == S.DONE.value:
            runner.go(S.RESTORE)
    res = execute({"function": {"name": "restore_batch", "arguments": {"batch_id": batch_id}}},
                  allowed={"read", "write"}, logger=h.log, run_id=run_id)
    if runner and runner.run.state == S.RESTORE.value:
        runner.go(S.DONE)
    return res


# ------------------------------------------------------------------- commands
def cmd_scan(a, cfg) -> int:
    root = Path(a.folder).expanduser()
    if not root.is_dir():
        print(f"Not a folder: {root}")
        return 2
    if not cfg.domain_rules and not a.dry_run:
        print(f"Config {cfg.name} disables the domain rules; it runs only with --dry-run.")
        return 2
    why = load_profile().refusal_reason(root.resolve())
    if why:                                   # refused before any file is read (UAT-08)
        print(f"CleanGuard will not scan {root}: {why}.")
        print("Nothing was read or moved. Choose a folder of your own files, such as Downloads.")
        return 2
    h = Harness()
    run = new_run(root, cfg, dry_run=a.dry_run)
    a.run, a.h = run, h
    runner = CleanGuardRun(h, run, cfg, progress=_progress)
    print(f"Scanning {run.root} (run {run.run_id}, config {cfg.name}"
          f"{', dry run: nothing can be moved' if a.dry_run else ''}) ...", flush=True)
    print(offline_line(h.config.base_url), flush=True)
    state = runner.until_pause()
    return _after(run, cfg, state)


def _progress(msg: str) -> None:
    print(f"  {msg}", flush=True)


def _after(run, cfg, state) -> int:
    if state == S.FAILED.value:
        if run.error == "LLMConnectionError":
            print(f"Run {run.run_id} stopped: CleanGuard could not connect to the local model "
                  "(Ollama is not running).")
            print("Nothing was moved. The files checked so far are saved.")
            print("Open the Ollama app again (or run `ollama serve`), then continue with:")
            print(f"    python -m cleanguard resume {run.run_id}")
        elif run.error == "ModelNotFoundError":
            models = load_config()
            tags = dict.fromkeys(models.profile(p).model for p in
                                 (cfg.routing.first_profile, cfg.routing.escalation_profile))
            print(f"Run {run.run_id} stopped: the model is not installed. Nothing was moved.")
            print("Pull it (" + " and ".join(f"`ollama pull {m}`" for m in tags)
                  + "), then continue with:")
            print(f"    python -m cleanguard resume {run.run_id}")
        else:
            print(f"Run {run.run_id} failed: {run.error}. Nothing was moved.")
        return 1
    print(console_summary(run, run_dir(run, cfg) / "report.html"))
    if state == S.APPROVE.value:
        print(f"Nothing has moved yet. Next: python -m cleanguard approve {run.run_id}")
    return 0


def cmd_resume(a, cfg) -> int:
    run = load_run(a.run_id, cfg)
    if run.state != S.FAILED.value:
        print(f"Run {run.run_id} is in state {run.state}; only a run that stopped (FAILED) "
              "can be resumed.")
        if run.state == S.APPROVE.value:
            print(f"It is waiting for you: python -m cleanguard approve {run.run_id}")
        return 2
    h = Harness()
    print(f"Resuming run {run.run_id} ...", flush=True)
    print(offline_line(h.config.base_url), flush=True)
    state = CleanGuardRun(h, run, cfg, progress=_progress).resume()
    return _after(run, cfg, state)


def cmd_clean(a, cfg) -> int:
    """Guided flow: scan, open the report, ask for approval, show the undo (UAT report item 6).
    The user never has to copy a run id between commands."""
    a.dry_run = False
    code = cmd_scan(a, cfg)
    run = getattr(a, "run", None)
    if code != 0 or run is None or run.state != S.APPROVE.value:
        return code
    report = (run_dir(run, cfg) / "report.html").resolve()
    if not a.no_open:
        webbrowser.open(report.as_uri())
        print("The report is open in your browser. Read it, then choose below.")
    approve(a.h, run, cfg)
    return 0


def cmd_ui(a, cfg) -> int:
    from .web.server import serve                  # only the web app needs this module
    return serve(cfg, port=a.port, open_browser=not a.no_open)


def cmd_approve(a, cfg) -> int:
    run = load_run(a.run_id, cfg)
    if run.state != S.APPROVE.value:
        print(f"Run {run.run_id} is in state {run.state}; only runs waiting in APPROVE can be approved.")
        if run.state == S.DONE.value:
            print(f"To move more files, scan the folder again: python -m cleanguard scan \"{run.root}\"")
        elif run.state == S.FAILED.value:
            print(f"It stopped before finishing. Continue with: python -m cleanguard resume {run.run_id}")
        return 2
    approve(Harness(), run, cfg)
    return 0


def _find_batch_run(batch_id: str, qdir: Path) -> str | None:
    m = Path(qdir) / batch_id / "manifest.json"
    return json.loads(m.read_text(encoding="utf-8")).get("run_id") if m.exists() else None


def cmd_restore(a, cfg) -> int:
    res = restore_flow(Harness(), cfg, a.batch_id)
    if not res["ok"]:
        print(f"Restore failed: {res['error']}")
        return 1
    r = res["result"]
    print(f"Restored {r['restored']} files from {a.batch_id}"
          + (f" ({r['renamed']} renamed with '(restored)' because the name was taken)" if r["renamed"] else "")
          + (f"; {r['missing']} were missing from the quarantine" if r["missing"] else "") + ".")
    return 0


def cmd_runs(a, cfg) -> int:
    rdir = Path(cfg.paths.runs_dir)
    states = sorted(rdir.glob("*/state.json"), key=lambda p: p.stat().st_mtime) if rdir.exists() else []
    print(f"Runs ({rdir}):" if states else "No runs yet.")
    for p in states:
        s = json.loads(p.read_text(encoding="utf-8"))
        labels = [d["label"] for d in s["decisions"].values()]
        print(f"  {s['run_id']}  {s['state']:<10} {s['config']:<8} {s['created_at']}  "
              f"{len(labels)} decided, {labels.count('deletable')} deletable  {s['root']}")
    qdir = load_profile().quarantine_dir
    batches = quarantine.list_batches(qdir) if qdir.exists() else []
    print(f"Quarantine ({qdir}):" if batches else f"Quarantine is empty ({qdir}).")
    for b in batches:
        print(f"  {b['batch_id']}  {b['status']:<12} {b['files']} files, {mb(b['bytes'])}  "
              f"from run {b['run_id']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cleanguard", description="CleanGuard: mark files keep / deletable / review; move only what you approve into a restorable quarantine.")
    ap.add_argument("--settings", default=str(DEFAULT_SETTINGS), help="path to cleanguard.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ui", help="open the local web app: scan, manage files, quarantine, chat")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-open", action="store_true", help="do not open a browser")
    p = sub.add_parser("clean", help="guided: scan, open the report, approve, show the undo")
    p.add_argument("folder")
    p.add_argument("--config", help="eval configuration from eval/configs.yaml, e.g. C4")
    p.add_argument("--no-open", action="store_true", help="do not open the report")
    p = sub.add_parser("scan", help="scan a folder and mark files")
    p.add_argument("folder")
    p.add_argument("--config", help="eval configuration from eval/configs.yaml, e.g. C4")
    p.add_argument("--dry-run", action="store_true", help="stop after the report")
    p = sub.add_parser("approve", help="choose files to move into quarantine")
    p.add_argument("run_id")
    p = sub.add_parser("restore", help="move a quarantine batch back")
    p.add_argument("batch_id")
    sub.add_parser("runs", help="list runs and quarantine batches")
    p = sub.add_parser("resume", help="continue a run that FAILED")
    p.add_argument("run_id")
    a = ap.parse_args(argv)
    cfg = load_settings(a.settings, getattr(a, "config", None))
    return {"ui": cmd_ui, "clean": cmd_clean, "scan": cmd_scan, "approve": cmd_approve,
            "restore": cmd_restore, "runs": cmd_runs, "resume": cmd_resume}[a.cmd](a, cfg)


if __name__ == "__main__":
    sys.exit(main())
