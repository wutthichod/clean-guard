"""Chat with the agent about a scan (read-only by design).

The model can look at results and PROPOSE: a selection of files, or a folder to scan. It cannot
do either. A proposal becomes a button the user clicks, and moving files still needs the typed
confirmation in the page. Sensitive files are never included in a proposed selection.

Only the tools listed in CHAT_TOOLS can run from chat. The executor alone is not enough for
that: it checks permission, not the list a model was offered, so read tools from the pipeline
such as scan_folder would otherwise be callable.

File names, reasons and user questions never reach the log: tool calls are logged by name with
no arguments. Only ids and counts are logged, as in the rest of CleanGuard.
"""
from __future__ import annotations

import re
import threading
import time
from typing import Literal, Optional

from pydantic import BaseModel, Field

from harness import (LLMConnectionError, LLMError, ModelNotFoundError, build_messages, err,
                     execute, tool_defs, tool_message)
from harness.tools import tool

from ..report import groups, mb
from .service import ServiceError

CHAT_TOOLS = ["scan_summary", "list_files", "file_details", "propose_selection", "propose_scan"]
MAX_ROUNDS = 3
MAX_CALLS_PER_ROUND = 4
MAX_MESSAGE_CHARS = 2000
MAX_HISTORY = 10
SNAPSHOT_FILES = 40

_lock = threading.Lock()      # one chat at a time: tools run in a pool and read this context
_ctx: dict = {"run": None, "actions": [], "service": None}


def _run():
    if _ctx["run"] is None:
        raise LookupError("no scan is open yet")
    return _ctx["run"]


def _row(r, d) -> dict:
    return {"file_id": r.file_id, "name": r.name, "folder": r.rel_path.rsplit("/", 1)[0] if "/" in r.rel_path else "",
            "size": mb(r.size_bytes), "age_days": r.modified_days, "label": d.label,
            "sensitive": d.sensitive, "reason": d.reason}


class NoArgs(BaseModel):
    pass


@tool(permission="read")
def scan_summary(args: NoArgs) -> dict:
    """How many files the open scan marked deletable, review, sensitive and keep, and how much
    space could be freed. Use for questions about the scan as a whole."""
    run = _run()
    g = groups(run)
    return {"folder": run.root.name, "files": len(run.records), "state": run.state,
            **{k: len(v) for k, v in g.items()},
            "reclaimable": mb(sum(r.size_bytes for r, _ in g["deletable"]))}


class ListArgs(BaseModel):
    group: Literal["all", "deletable", "review", "sensitive", "keep"] = Field(
        default="all", description="Which group of files to list")
    contains: Optional[str] = Field(default=None, description="Only names containing this text")
    limit: int = Field(default=15, ge=1, le=40, description="How many files, largest first")


@tool(permission="read")
def list_files(args: ListArgs) -> dict:
    """List files from the open scan with their label, size and reason, largest first. Use to
    answer which files are in a group, or to find a file by name."""
    g = groups(_run())
    rows = [x for name, v in g.items() if args.group in ("all", name) for x in v]
    if args.contains:
        rows = [x for x in rows if args.contains.lower() in x[0].name.lower()]
    rows.sort(key=lambda x: -x[0].size_bytes)
    return {"total": len(rows), "files": [_row(r, d) for r, d in rows[:args.limit]]}


class DetailArgs(BaseModel):
    file_id: str = Field(pattern=r"^f\d{4,6}$", description="ID of a file, e.g. f0007")


@tool(permission="read")
def file_details(args: DetailArgs) -> dict:
    """Why one file got its label: reason, who decided, age, size and any duplicate."""
    run = _run()
    if args.file_id not in run.decisions:
        raise LookupError(f"{args.file_id} is not in this scan")
    r, d = run.records[args.file_id], run.decisions[args.file_id]
    dup = run.records[r.dup_of].rel_path if r.dup_of in run.records else None
    return {**_row(r, d), "sensitive_type": d.sensitive_type, "decided_by": d.decided_by,
            "exact_copy_of": dup}


class SelectArgs(BaseModel):
    file_ids: list[str] = Field(description="IDs of files to suggest", max_length=200)


@tool(permission="read")
def propose_selection(args: SelectArgs) -> dict:
    """Suggest files for the user to tick in the file list. This moves nothing and selects
    nothing: the user sees a button, and must confirm any move themselves."""
    run = _run()
    ok, left_out = [], 0
    for f in dict.fromkeys(args.file_ids):
        d, r = run.decisions.get(f), run.records.get(f)
        if d is not None and r is not None and d.label in ("deletable", "review") \
                and not d.sensitive and not r.protected:
            ok.append(f)
        else:
            left_out += 1
    if ok:
        _ctx["actions"].append({"type": "select", "file_ids": ok})
    return {"suggested": len(ok), "left_out": left_out,
            "note": "Sensitive and keep files are never suggested. The user decides."}


class ScanArgs(BaseModel):
    folder: str = Field(description="Folder the user asked to scan", max_length=1024)


@tool(permission="read")
def propose_scan(args: ScanArgs) -> dict:
    """Offer the user a button to scan a folder they asked about. This starts nothing."""
    from pathlib import Path
    root = Path(args.folder).expanduser()
    if not root.is_dir():
        return {"proposed": False, "note": "That folder does not exist."}
    why = _ctx["service"].profile.refusal_reason(root.resolve())
    if why:
        return {"proposed": False, "note": f"CleanGuard refuses this folder: {why}."}
    _ctx["actions"].append({"type": "scan", "folder": str(root)})
    return {"proposed": True}


class Chat:
    def __init__(self, service):
        self.service = service
        self.history: dict[str, list[dict]] = {}   # per run; in memory only

    def reset(self, run_id: str | None) -> None:
        self.history.pop(run_id or "none", None)

    def ask(self, message: str, run_id: str | None = None) -> dict:
        message = (message or "").strip()
        if not message:
            raise ServiceError(400, "Type a question first.")
        if len(message) > MAX_MESSAGE_CHARS:
            raise ServiceError(400, f"Keep questions under {MAX_MESSAGE_CHARS} characters.")
        run = self.service._load(run_id) if run_id else None
        h = self.service.make_harness()
        log_id = run_id or "r-chat"
        key = run_id or "none"
        with _lock:
            _ctx.update(run=run, actions=[], service=self.service)
            try:
                reply, used = self._loop(h, message, run, log_id, self.history.get(key, []))
            except LLMConnectionError:
                raise ServiceError(503, "The local model is not reachable. Open the Ollama app and "
                                        "try again. File actions still work.", kind="model_down") from None
            except ModelNotFoundError:
                raise ServiceError(503, "The local model is not installed. Pull it with ollama, "
                                        "then try again.", kind="model_down") from None
            except LLMError:
                raise ServiceError(502, "The local model did not answer. Try again.") from None
            actions = list(_ctx["actions"])
            _ctx.update(run=None, actions=[])
        hist = self.history.setdefault(key, [])
        hist += [{"role": "user", "content": message}, {"role": "assistant", "content": reply}]
        del hist[:-MAX_HISTORY]
        return {"reply": reply, "actions": actions, "tools_used": used}

    def _loop(self, h, message, run, log_id, history) -> tuple[str, list[str]]:
        p = h.prompts.get("chat_assistant")
        context = self._context(run)
        msgs = build_messages(p.render(), static_context=context, history=history,
                              observations=self._snapshot(run), user=message)
        profile = self.service.cfg.routing.first_profile
        used: list[str] = []
        for _ in range(MAX_ROUNDS):
            r = h.llm(profile, msgs, tools=tool_defs(CHAT_TOOLS), run_id=log_id, prompt_id=p.id)
            if not r.tool_calls:
                return self._clean(r.content), used
            msgs.append(r.message)
            for call in r.tool_calls[:MAX_CALLS_PER_ROUND]:
                name = call.get("function", {}).get("name", "")
                t = time.perf_counter()
                res = execute(call, allowed={"read"}) if name in CHAT_TOOLS else \
                    err(f"Tool {name!r} is not available in chat. Available: {CHAT_TOOLS}")
                # no arguments here: they can hold file names, and the log never holds names
                h.log.tool_call(run_id=log_id, name=name if name in CHAT_TOOLS else "unavailable",
                                arguments={}, ok=res["ok"], duration_s=time.perf_counter() - t,
                                source="chat")
                used.append(name)
                msgs.append(tool_message(call, res))
        r = h.llm(profile, msgs, run_id=log_id, prompt_id=p.id)   # out of rounds: answer now
        return self._clean(r.content), used

    @staticmethod
    def _snapshot(run) -> list[dict]:
        """The scan's files, as if the model had already called list_files. A small model often
        answers without calling a tool, and then cannot name a single file. File names are
        untrusted, so they arrive as a tool result, never in the system prompt."""
        if run is None:
            return []
        call = {"function": {"name": "list_files", "arguments": {"limit": SNAPSHOT_FILES}}}
        return [{"role": "assistant", "content": "", "tool_calls": [call]},
                tool_message(call, execute(call, allowed={"read"}))]

    @staticmethod
    def _clean(text: str) -> str:
        text = re.sub(r"\*\*|`", "", text or "").strip()      # the page shows plain text
        return text or "I could not form an answer. Try asking in another way."

    @staticmethod
    def _context(run) -> str:
        if run is None:
            return "No scan is open. Ask the user to choose a folder and press Scan."
        g = groups(run)
        return (f"The open scan: folder \"{run.root.name}\", state {run.state}, "
                f"{len(run.records)} files: {len(g['deletable'])} deletable, {len(g['review'])} review, "
                f"{len(g['sensitive'])} sensitive, {len(g['keep'])} keep. "
                f"{mb(sum(r.size_bytes for r, _ in g['deletable']))} could be freed.")
