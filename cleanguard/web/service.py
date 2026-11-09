"""What the web app can do. No HTTP here, so every rule can be tested directly.

One pipeline runs at a time, because a CleanGuard process has one active run (run_context).
Scans and resumes run in a background thread and report progress for the page to poll.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import threading
from pathlib import Path

from harness import Harness

from .. import cli, quarantine
from ..platform import load_profile
from ..report import groups, mb
from ..safety import ensure_inside
from ..settings import Settings
from ..snippets import SUPPORTED, extract_text
from ..state_machine import S, CleanGuardRun, load_run, new_run

RUN_ID = re.compile(r"^r-[0-9a-f]{8}$")
FILE_ID = re.compile(r"^f\d{4,6}$")
BATCH_ID = re.compile(r"^q-\d{8}-\d{6}-[0-9a-f]{4}$")
PREVIEW_CHARS = 4000
PREVIEW_MAX_MB = 20


class ServiceError(Exception):
    def __init__(self, status: int, message: str, kind: str = "error"):
        super().__init__(message)
        self.status, self.message, self.kind = status, message, kind


class Service:
    def __init__(self, cfg: Settings, harness_factory=Harness, profile=None):
        self.cfg, self.make_harness = cfg, harness_factory
        self.profile = profile or load_profile()
        self._busy = threading.Lock()              # held while the pipeline runs
        self._jobs: dict[str, dict] = {}           # run_id -> progress of background work
        self._state_lock = threading.Lock()

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        h = self.make_harness()
        r = self.cfg.routing
        need = list(dict.fromkeys(h.config.profile(p).model
                                  for p in (r.first_profile, r.escalation_profile)))
        reachable, missing = True, []
        try:
            names = h.client.list_models()
            missing = [m for m in need if m not in names]
        except Exception:  # noqa: BLE001 - any failure means the model cannot be used right now
            reachable = False
        return {"model_reachable": reachable, "models": need, "models_missing": missing,
                "offline_line": cli.offline_line(h.config.base_url), "os": self.profile.name,
                "quarantine_dir": Path(self.profile.quarantine_dir).as_posix(),
                "busy": self._busy.locked(), "shortcuts": self._shortcuts()}

    def _shortcuts(self) -> list[dict]:
        home = Path.home()
        out = [("Downloads", home / "Downloads"), ("Documents", home / "Documents"),
               ("Desktop", home / "Desktop"), ("UAT folders", Path.cwd() / "uat_folders")]
        return [{"name": n, "path": str(p)} for n, p in out if p.is_dir()]

    # ------------------------------------------------------------------ browse
    def browse(self, path: str | None) -> dict:
        """List subfolders so the user can pick one. Names only; files are not listed."""
        p = Path(path).expanduser() if path else Path.home()
        try:
            p = p.resolve(strict=True)
            if not p.is_dir():
                raise ServiceError(400, f"Not a folder: {p}")
            folders = []
            with os.scandir(p) as it:
                for e in it:
                    if e.name.startswith("."):
                        continue
                    try:
                        if e.is_dir(follow_symlinks=False):
                            child = p / e.name
                            folders.append({"name": e.name, "path": str(child),
                                            "refused": self.profile.refusal_reason(child)})
                    except OSError:
                        continue
        except FileNotFoundError:
            raise ServiceError(404, f"Folder not found: {path}") from None
        except PermissionError:
            raise ServiceError(403, f"No permission to open {path}. On macOS, allow Files and "
                                    "Folders access for your terminal.") from None
        except OSError as e:
            raise ServiceError(400, f"Cannot open {path} ({type(e).__name__})") from None
        folders.sort(key=lambda x: x["name"].lower())
        return {"path": str(p), "parent": str(p.parent) if p.parent != p else None,
                "refused": self.profile.refusal_reason(p), "folders": folders[:1000]}

    # ------------------------------------------------------------------ scan / resume
    def start_scan(self, folder: str, dry_run: bool = False) -> dict:
        folder = (folder or "").strip()
        if not folder:
            raise ServiceError(400, "Choose a folder to scan.")
        root = Path(folder).expanduser()
        if not root.is_dir():
            raise ServiceError(400, f"Not a folder: {root}")
        why = self.profile.refusal_reason(root.resolve())
        if why:                                    # refused before any file is read (UAT-08)
            raise ServiceError(400, f"CleanGuard will not scan {root}: {why}. Nothing was read "
                                    "or moved.", kind="refused")
        if not self._busy.acquire(blocking=False):
            raise ServiceError(409, "Another scan is running. Wait for it to finish.")
        try:
            h = self.make_harness()
            run = new_run(root, self.cfg, profile=self.profile, dry_run=dry_run)
        except Exception:
            self._busy.release()
            raise
        self._start_job(run, h, lambda r: r.until_pause(), f"Scanning {run.root} ...")
        return {"run_id": run.run_id}

    def resume(self, run_id: str) -> dict:
        run = self._load(run_id)
        if run.state != S.FAILED.value:
            raise ServiceError(409, f"Only a stopped run can be resumed; this one is {run.state}.")
        if not self._busy.acquire(blocking=False):
            raise ServiceError(409, "Another scan is running. Wait for it to finish.")
        try:
            h = self.make_harness()
        except Exception:
            self._busy.release()
            raise
        self._start_job(run, h, lambda r: r.resume(), "Resuming ...")
        return {"run_id": run_id}

    def _start_job(self, run, h, work, first_line) -> None:
        job = {"active": True, "progress": [first_line], "root": str(run.root),
               "dry_run": run.dry_run, "error": None}
        with self._state_lock:
            self._jobs[run.run_id] = job

        def target():
            try:
                runner = CleanGuardRun(h, run, self.cfg, progress=job["progress"].append)
                work(runner)
            except Exception as e:  # noqa: BLE001 - shown to the user; the run file holds the state
                job["error"] = f"{type(e).__name__}: the scan stopped unexpectedly. Nothing was moved."
            finally:
                job["active"] = False
                self._busy.release()

        threading.Thread(target=target, daemon=True, name=f"scan-{run.run_id}").start()

    # ------------------------------------------------------------------ runs
    def _check_run_id(self, run_id: str) -> None:
        if not RUN_ID.match(run_id or ""):
            raise ServiceError(404, "Unknown run.")

    def _load(self, run_id: str):
        self._check_run_id(run_id)
        for attempt in range(3):                   # Windows may briefly lock a file being replaced
            try:
                return load_run(run_id, self.cfg)
            except FileNotFoundError:
                raise ServiceError(404, "Unknown run.") from None
            except (PermissionError, json.JSONDecodeError):
                if attempt == 2:
                    raise ServiceError(503, "The run is being saved. Try again.") from None
                threading.Event().wait(0.1)

    def list_runs(self) -> list[dict]:
        rdir = Path(self.cfg.paths.runs_dir)
        out = {}
        for p in rdir.glob("*/state.json") if rdir.exists() else []:
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            labels = [d["label"] for d in s["decisions"].values()]
            out[s["run_id"]] = {"run_id": s["run_id"], "state": s["state"], "root": s["root"],
                                "created_at": s["created_at"], "files": len(labels),
                                "deletable": labels.count("deletable"), "dry_run": s["dry_run"]}
        with self._state_lock:
            jobs = dict(self._jobs)
        for run_id, j in jobs.items():
            if j["active"]:
                row = out.setdefault(run_id, {"run_id": run_id, "root": j["root"], "created_at": "",
                                              "files": 0, "deletable": 0, "dry_run": j["dry_run"],
                                              "state": "SCAN"})
                row["active"] = True
        return sorted(out.values(), key=lambda r: r["created_at"] or "9", reverse=True)

    def run_detail(self, run_id: str) -> dict:
        self._check_run_id(run_id)
        job = self._jobs.get(run_id)
        if job and job["active"] and not (Path(self.cfg.paths.runs_dir) / run_id / "state.json").exists():
            return {"run_id": run_id, "state": "SCAN", "active": True, "root": job["root"],
                    "progress": list(job["progress"]), "files": [], "summary": None,
                    "dry_run": job["dry_run"], "can_move": False}
        run = self._load(run_id)
        moved = self._moved_files(run_id)
        selectable = self._selectable_ids(run)
        g = groups(run)
        group_of = {r.file_id: name for name, rows in g.items() for r, _ in rows}
        files = []
        for f, d in run.decisions.items():
            r = run.records[f]
            files.append({"file_id": f, "name": r.name, "rel_path": r.rel_path,
                          "folder": r.rel_path.rsplit("/", 1)[0] if "/" in r.rel_path else "",
                          "size_bytes": r.size_bytes, "size": mb(r.size_bytes),
                          "age_days": r.modified_days, "label": d.label, "sensitive": d.sensitive,
                          "sensitive_type": d.sensitive_type, "reason": d.reason,
                          "decided_by": d.decided_by, "group": group_of.get(f, "keep"),
                          "selectable": f in selectable, "batch_id": moved.get(f),
                          "previewable": r.ext in SUPPORTED})
        active = bool(job and job["active"])
        size = {k: sum(r.size_bytes for r, _ in rows) for k, rows in g.items()}
        return {"run_id": run_id, "state": run.state, "root": run.root.as_posix(),
                "active": active, "dry_run": run.dry_run, "created_at": run.created_at,
                "failed_from": run.failed_from, "error": run.error,
                "job_error": job["error"] if job else None,
                "progress": list(job["progress"]) if job else [],
                "can_move": run.state == S.APPROVE.value and not active,
                "can_resume": run.state == S.FAILED.value and not active,
                "files_found": len(run.records),
                "summary": {"deletable": len(g["deletable"]), "review": len(g["review"]),
                            "sensitive": len(g["sensitive"]), "keep": len(g["keep"]),
                            "reclaimable_bytes": size["deletable"],
                            "reclaimable": mb(size["deletable"]), "sizes": {k: mb(v) for k, v in size.items()}},
                "files": files}

    @staticmethod
    def _selectable_ids(run) -> set[str]:
        dele, revw, sens = cli.selectable_groups(run)
        return {x[0].file_id for group in (dele, revw, sens) for x in group.values()}

    def _moved_files(self, run_id: str) -> dict[str, str]:
        """file_id -> batch_id for files of this run that are in quarantine now."""
        out = {}
        for b in self._read_batches():
            if b.get("run_id") == run_id:
                for e in b["entries"]:
                    if e["status"] == "moved":
                        out[e["file_id"]] = b["batch_id"]
        return out

    # ------------------------------------------------------------------ moving files
    def move(self, run_id: str, file_ids: list[str], confirm: str, sensitive_confirm: str = "") -> dict:
        """Requires the user's typed words, checked here and not only in the page."""
        if confirm != "MOVE":
            raise ServiceError(400, "Type MOVE to confirm. Nothing was moved.")
        if not isinstance(file_ids, list) or not file_ids or \
                not all(isinstance(f, str) and FILE_ID.match(f) for f in file_ids):
            raise ServiceError(400, "Choose at least one file. Nothing was moved.")
        file_ids = list(dict.fromkeys(file_ids))
        if not self._busy.acquire(blocking=False):
            raise ServiceError(409, "A scan is running. Wait for it to finish.")
        try:
            run = self._load(run_id)
            if run.state != S.APPROVE.value:
                raise ServiceError(409, "This run can no longer move files. Scan the folder again.")
            bad = [f for f in file_ids if f not in self._selectable_ids(run)]
            if bad:
                raise ServiceError(403, f"{len(bad)} file(s) cannot be moved (marked keep or "
                                        "protected). Nothing was moved.")
            sens = [f for f in file_ids if run.decisions[f].sensitive]
            if sens and sensitive_confirm != "SENSITIVE":
                raise ServiceError(400, f"{len(sens)} file(s) may hold personal data. Type SENSITIVE "
                                        "to include them. Nothing was moved.", kind="needs_sensitive")
            lines: list[str] = []
            res = cli.quarantine_selection(self.make_harness(), run, self.cfg, file_ids, sens,
                                           lines.append)
            if not res["ok"]:
                raise ServiceError(500, "The move was refused. Nothing was moved.")
            q = res["result"]
            skipped = [{"file_id": s["file_id"], "name": run.records[s["file_id"]].rel_path,
                        "why": cli.skip_reason(s["status"])} for s in q["skipped"]]
            return {"status": q["status"], "batch_id": q["batch_id"], "moved": len(q["moved"]),
                    "size": mb(q["bytes"]), "skipped": skipped,
                    "sensitive_confirmed": len(sens) if q["status"] != "rolled_back" else 0}
        finally:
            self._busy.release()

    # ------------------------------------------------------------------ one file
    def _existing_path(self, run_id: str, file_id: str):
        run = self._load(run_id)
        rec = run.records.get(file_id)
        if not FILE_ID.match(file_id or "") or rec is None:
            raise ServiceError(404, "Unknown file.")
        try:
            return run, rec, ensure_inside(run.root, rec.abs_path)
        except FileNotFoundError:
            raise ServiceError(404, "This file is no longer in its folder (moved or removed).",
                               kind="gone") from None
        except PermissionError:
            raise ServiceError(403, "This file is outside the scanned folder.") from None

    def preview(self, run_id: str, file_id: str) -> dict:
        _, rec, path = self._existing_path(run_id, file_id)
        if rec.ext not in SUPPORTED:
            return {"text": None, "note": f"No preview for {rec.ext or 'this file type'} files."}
        if path.stat().st_size > PREVIEW_MAX_MB * 1024 * 1024:
            return {"text": None, "note": f"Too large to preview (over {PREVIEW_MAX_MB} MB)."}
        try:
            text = extract_text(path, PREVIEW_CHARS)
        except Exception:  # noqa: BLE001 - broken files are expected
            return {"text": None, "note": "This file could not be read."}
        return {"text": text, "note": f"First {PREVIEW_CHARS:,} characters at most."}

    def reveal(self, run_id: str, file_id: str) -> dict:
        """Show the file in Finder or Explorer. Never runs or opens the file itself."""
        _, _, path = self._existing_path(run_id, file_id)
        system = platform.system()
        if system == "Darwin":
            cmd = ["open", "-R", str(path)]
        elif system == "Windows":
            cmd = ["explorer", f"/select,{path}"]
        else:
            cmd = ["xdg-open", str(path.parent)]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
        except OSError:
            raise ServiceError(500, "Could not open the file manager.") from None
        return {"ok": True}

    # ------------------------------------------------------------------ quarantine
    def _read_batches(self) -> list[dict]:
        out = []
        for m in sorted(Path(self.profile.quarantine_dir).glob("q-*/manifest.json")):
            try:
                out.append(json.loads(m.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return out

    def list_quarantine(self) -> dict:
        batches = []
        for b in reversed(self._read_batches()):
            held = [e for e in b["entries"] if e["status"] == "moved"]
            batches.append({
                "batch_id": b["batch_id"], "run_id": b.get("run_id"), "status": b["status"],
                "created_at": b.get("created_at"), "restored_at": b.get("restored_at"),
                "files": len(held), "size": mb(sum(e["size_bytes"] for e in held)),
                "can_restore": bool(held),
                "entries": [{"name": Path(e["original_path"]).name, "original_path": e["original_path"],
                             "size": mb(e["size_bytes"]), "status": e["status"],
                             "restored_to": e.get("restored_to")} for e in b["entries"]]})
        return {"dir": Path(self.profile.quarantine_dir).as_posix(), "batches": batches,
                "total": mb(quarantine.quarantine_size(self.profile.quarantine_dir))
                if Path(self.profile.quarantine_dir).exists() else mb(0)}

    def restore(self, batch_id: str) -> dict:
        if not BATCH_ID.match(batch_id or ""):
            raise ServiceError(404, "Unknown batch.")
        if not self._busy.acquire(blocking=False):
            raise ServiceError(409, "A scan is running. Wait for it to finish.")
        try:
            res = cli.restore_flow(self.make_harness(), self.cfg, batch_id,
                                   self.profile.quarantine_dir)
        finally:
            self._busy.release()
        if not res["ok"]:
            raise ServiceError(404 if "LookupError" in res["error"] else 500, "Restore failed.")
        r = res["result"]
        return {"restored": r["restored"], "renamed": r["renamed"], "missing": r["missing"]}
