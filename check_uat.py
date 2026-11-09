"""Check one UAT task against data/test_set.jsonl.

    python check_uat.py --task T04 --run runs/<run_id>
    python check_uat.py --task T02                      # folder-only checks

Exit code 0 = every automatic check passed. Manual checks are printed for the observer.
uat_session.py imports evaluate() from here.
"""
import argparse, hashlib, json, os, platform, sys
from pathlib import Path

INSTALLER = (".exe", ".dmg")
LABELS = ("keep", "deletable", "review")
REPORT_OR_LATER = {"REPORT", "APPROVE", "QUARANTINE", "DONE", "RESTORE"}


def this_os() -> str:
    return {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "macos")


def expand(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def load_targets(cfg_path="uat_config.json", os_name=None) -> dict:
    """{protected_root} / {cloud_root} placeholders of T08 / T09 -> this laptop's paths."""
    cfg_path = Path(cfg_path)
    if not cfg_path.exists():
        return {}
    cfg, osn = json.loads(cfg_path.read_text(encoding="utf-8")), os_name or this_os()
    return {"{protected_root}": expand(cfg["protected_target"][osn]),
            "{cloud_root}": expand(cfg["cloud_target"][osn])}


def load_tasks(tests: Path) -> list:
    return [json.loads(l) for l in Path(tests).read_text(encoding="utf-8").splitlines() if l.strip()]


def find_task(tasks: list, task_id: str) -> dict:
    for t in tasks:
        if t["id"] == task_id:
            return t
    raise SystemExit(f"unknown task {task_id}")


def folder_specs(tasks: list, folder: str) -> list:
    """Files of a folder; tasks that reuse a folder (T02, T05) have no 'files' of their own."""
    for t in tasks:
        if t.get("folder") == folder and t.get("files"):
            return t["files"]
    return []


def _find(d: dict, *keys):
    for k in keys:
        if k in d:
            return d[k]
    return None


def load_run(run_dir: Path) -> dict:
    """rel_path -> {label, sensitive, reason}.

    Expects runs/<run_id>/state.json with "decisions" keyed by file_id, and files.json mapping
    file_id -> {"rel_path": ...}. If your run files differ, change only this function.
    """
    run_dir = Path(run_dir)
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    files = json.loads((run_dir / "files.json").read_text(encoding="utf-8"))
    out = {}
    for fid, d in state["decisions"].items():
        f = files.get(fid, {})
        rel = _find(f, "rel_path", "path", "name") if isinstance(f, dict) else f
        out[str(rel).replace("\\", "/")] = {
            "label": d.get("label"),
            "sensitive": bool(d.get("sensitive")),
            "reason": d.get("reason", ""),
        }
    return out


def resolve(spec_path: str, manifest: dict) -> str:
    if "{inst}" not in spec_path:
        return spec_path
    for ext in INSTALLER:
        name = spec_path.replace("{inst}", ext)
        if name in manifest:
            return name
    return spec_path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refusal_checks(target: Path, runs_dir: Path, check) -> None:
    """T08 / T09: CleanGuard must refuse the folder before reading any file in it."""
    try:
        from cleanguard.platform import load_profile       # the kit sits at the CleanGuard root
        why = load_profile().refusal_reason(target.resolve())
        check("CleanGuard refuses this folder", why is not None, why or f"{target} would be scanned")
    except ImportError:
        check("CleanGuard refuses this folder", False, "run from the repository root")
    read = []
    if Path(runs_dir).exists():
        want = target.resolve().as_posix().rstrip("/").lower()
        for st in Path(runs_dir).glob("*/state.json"):
            s = json.loads(st.read_text(encoding="utf-8"))
            if str(s.get("root", "")).rstrip("/").lower() != want:
                continue
            files = st.parent / "files.json"
            n = len(json.loads(files.read_text(encoding="utf-8"))) if files.exists() else 0
            if n or s.get("decisions"):
                read.append(f"{st.parent.name}: {n} files")
    check("0 files read from it", not read, "; ".join(read))


def evaluate(task: dict, tasks: list, folders: Path, run_dir=None, targets=None,
             runs_dir="runs") -> dict:
    """Run every automatic check for one task. Returns a dict with checks and counts."""
    exp = task["expected"]
    res = {"task": task["id"], "uat": task["uat"], "type": task["type"], "checks": [],
           "labeled": 0, "acceptable": 0, "sensitive_total": 0, "sensitive_flagged": 0,
           "sensitive_deletable": 0, "manual": task.get("manual", [])}

    def check(name, ok, detail=""):
        res["checks"].append({"name": name, "ok": bool(ok), "detail": detail})

    if task.get("folder") is None:
        target = (targets or {}).get(task.get("target"))
        if exp.get("refused") and target is not None:
            refusal_checks(Path(target), Path(runs_dir), check)
            res["note"] = "the refusal message and the user's explanation come from the observer sheet"
        else:
            res["note"] = "no folder: result comes from the observer sheet"
        return res

    folders = Path(folders)
    manifest = json.loads((folders / f"{task['folder']}.manifest.json").read_text(encoding="utf-8"))
    specs = {resolve(s["path"], manifest): s for s in folder_specs(tasks, task["folder"])}
    root = folders / task["folder"]
    sens = [p for p, s in specs.items() if s["sensitive"]]
    res["sensitive_total"] = len(sens)

    if exp.get("labels"):
        if run_dir is None:
            check("run found for this task", False, "pass --run runs/<run_id>")
        else:
            labels = load_run(Path(run_dir))
            missing = [p for p in specs if p not in labels]
            check("every file labeled", not missing, ", ".join(missing))
            wrong = [f"{p}: {labels[p]['label']}" for p, s in specs.items()
                     if p in labels and labels[p]["label"] not in s["acceptable"]]
            res["labeled"] = sum(p in labels for p in specs)
            res["acceptable"] = res["labeled"] - len(wrong)
            check("labels in acceptable set", not wrong, "; ".join(wrong))
            sens_del = [p for p in sens if labels.get(p, {}).get("label") == "deletable"]
            res["sensitive_deletable"] = len(sens_del)
            res["sensitive_flagged"] = sum(labels.get(p, {}).get("sensitive", False) for p in sens)
            check("HARD GATE: 0 sensitive files deletable", not sens_del, ", ".join(sens_del))
            if "min_sensitive_flagged" in exp:
                check(f"at least {exp['min_sensitive_flagged']} sensitive files flagged",
                      res["sensitive_flagged"] >= exp["min_sensitive_flagged"],
                      f"{res['sensitive_flagged']} of {len(sens)}")
            if exp.get("final_state") == "REPORT_OR_LATER":         # T06: resumed to the report
                state = json.loads((Path(run_dir) / "state.json").read_text(encoding="utf-8"))["state"]
                check("run reached the report after the failure", state in REPORT_OR_LATER, state)

    may_change = {resolve(p, manifest) for p in exp.get("present", [])}
    # a later task on the same folder may legitimately move a file (T05 after T04), so allow it for all of them
    may_move = {resolve(p, manifest) for t in tasks if t.get("folder") == task["folder"]
                for p in t["expected"].get("may_move", [])}
    must_stay = {p for p, s in specs.items() if "deletable" not in s["acceptable"] or s["sensitive"]}
    if exp.get("all_present_unchanged"):
        must_stay = set(specs)
    must_stay = (must_stay - may_move) | may_change
    if exp.get("never_moved") or exp.get("all_present_unchanged") or may_change:
        bad = []
        for p in sorted(must_stay):
            f = root / p
            if not f.exists():
                bad.append(f"{p} missing")
            elif p not in may_change and sha256(f) != manifest[p]:
                bad.append(f"{p} changed")
        check("no needed file lost or changed", not bad, "; ".join(bad))
    if task["type"] == "happy" and may_change:              # T02: the restored file is the original
        diff = [p for p in sorted(may_change) if (root / p).exists() and sha256(root / p) != manifest[p]]
        check("restored file identical to the original", not diff, ", ".join(diff))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--tests", default="data/test_set.jsonl")
    ap.add_argument("--folders", default="uat_folders")
    ap.add_argument("--run")
    ap.add_argument("--runs-dir", default="runs")
    a = ap.parse_args()
    tasks = load_tasks(Path(a.tests))
    r = evaluate(find_task(tasks, a.task), tasks, Path(a.folders), a.run, load_targets(), a.runs_dir)
    print(f"{r['task']} · {r['uat']} · {r['type']}")
    for c in r["checks"]:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['name']}" + (f"  ({c['detail']})" if c["detail"] else ""))
    if r.get("note"):
        print(r["note"])
    for m in r["manual"]:
        print(f"MANUAL  {m}")
    sys.exit(0 if all(c["ok"] for c in r["checks"]) else 1)


if __name__ == "__main__":
    main()
