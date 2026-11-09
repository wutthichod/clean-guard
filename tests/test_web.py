"""Web app (offline): real HTTP against a real server on a free port, with a fake model.

The server can move files, so most of this is about who may ask it to, and that chat never can.
"""
import json
import os
import re
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).parent))
from _cg_util import (_files_in, make_file, make_harness, profile, settings,  # noqa: E402
                      tmpdir)

from harness import LLMConnectionError  # noqa: E402

from cleanguard import run_context  # noqa: E402
from cleanguard.web.server import STATIC, App, Server  # noqa: E402
from cleanguard.web.service import Service  # noqa: E402

LABELS = {"setup_zoom.exe": ("deletable", False), "report (1).pdf": ("deletable", False),
          "mystery.bin": ("review", False), "cv.pdf": ("keep", False),
          "passport.txt": ("keep", True), "passport (1).txt": ("keep", True),
          "statement.bin": ("review", True)}


def model(m, messages, schema=None, tools=None, **kw):
    """Labels from LABELS; chat tools are off unless a test queues outputs."""
    if tools:
        return "DONE"
    is_privacy = "label" not in json.dumps(schema or {})
    out = []
    for f in _files_in(messages):
        label, sens = LABELS.get(f["name"], ("keep", False))
        v = {"file_id": f["file_id"], "sensitive": sens, "sensitive_type": "id_doc" if sens else "none",
             "reason": "Fake model answer."}
        if not is_privacy:
            v["label"] = label
        out.append(v)
    return json.dumps({"verdicts": out})


class WebBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.root = self.tmp / "folder"
        make_file(self.root, "setup_zoom.exe", os.urandom(4000), 400)
        make_file(self.root, "report.pdf", b"same bytes here", 200)
        make_file(self.root, "report (1).pdf", b"same bytes here", 199)
        make_file(self.root, "mystery.bin", os.urandom(50), 300)
        make_file(self.root, "cv.pdf", os.urandom(60), 100)
        make_file(self.root, "passport.txt", "Passport No. AA1234567", 300)
        make_file(self.root, "passport (1).txt", "Passport No. AA1234567", 299)
        self.cfg = settings(self.tmp)
        self.h = make_harness(self, auto=model)
        self.h.client.list_models = lambda: [self.h.config.profile("fast").model,
                                             self.h.config.profile("reasoning").model]
        self.service = Service(self.cfg, harness_factory=lambda: self.h, profile=profile(self.tmp))
        self.app = App(self.service)
        self.srv = Server(self.app, 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self._stop)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.auth = {"X-CleanGuard-Token": self.app.token}

    def _stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        run_context.set_active(None)

    def get(self, path, **kw):
        return requests.get(self.base + path, headers=self.auth, timeout=10, **kw)

    def post(self, path, body=None, **kw):
        return requests.post(self.base + path, json=body or {}, headers=self.auth, timeout=10, **kw)

    def scan(self, dry_run=False) -> dict:
        r = self.post("/api/scan", {"folder": str(self.root), "dry_run": dry_run})
        self.assertEqual(r.status_code, 200, r.text)
        return self.wait(r.json()["run_id"])

    def wait(self, run_id) -> dict:
        for _ in range(200):
            d = self.get(f"/api/runs/{run_id}").json()
            if not d.get("active"):
                return d
            time.sleep(0.02)
        self.fail("scan did not finish")

    def ids(self, run, *names):
        by = {f["name"]: f["file_id"] for f in run["files"]}
        return [by[n] for n in names]

    def file(self, run, name):
        return next(f for f in run["files"] if f["name"] == name)


class TestWhoCanAsk(WebBase):
    def test_binds_to_loopback_only(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")

    def test_other_hosts_are_rejected_stops_dns_rebinding(self):
        for path in ("/", "/api/runs"):
            r = requests.get(self.base + path, headers={**self.auth, "Host": "evil.example"}, timeout=5)
            self.assertEqual(r.status_code, 403, path)
            self.assertNotIn(self.app.token, r.text)

    def test_api_needs_the_token(self):
        self.assertEqual(requests.get(self.base + "/api/runs", timeout=5).status_code, 403)
        bad = {"X-CleanGuard-Token": "wrong"}
        self.assertEqual(requests.get(self.base + "/api/runs", headers=bad, timeout=5).status_code, 403)
        r = requests.post(self.base + "/api/scan", json={"folder": str(self.root)}, timeout=5)
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Path(self.cfg.paths.runs_dir).exists())

    def test_post_from_another_origin_is_rejected(self):
        r = requests.post(
            self.base + "/api/scan", json={"folder": str(self.root)},
            headers={**self.auth, "Origin": "https://evil.example"}, timeout=5)
        self.assertEqual(r.status_code, 403)

    def test_post_must_be_json(self):
        r = requests.post(self.base + "/api/scan", data="folder=/tmp",
                          headers={**self.auth, "Content-Type": "text/plain"}, timeout=5)
        self.assertEqual(r.status_code, 415)

    def test_page_headers_and_token(self):
        r = requests.get(self.base + "/", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.app.token, r.text)
        self.assertNotIn("__TOKEN__", r.text)
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe", csp)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_page_loads_nothing_from_outside_and_never_writes_html(self):
        for name in ("index.html", "app.js", "style.css"):
            text = (STATIC / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"https?://", text), name)
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertNotRegex(js, r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(")

    def test_static_files_are_a_fixed_list(self):
        for path in ("/static/../server.py", "/static/..%2fserver.py", "/server.py", "/static/index.html"):
            self.assertEqual(requests.get(self.base + path, timeout=5).status_code, 404, path)

    def test_bad_ids_cannot_reach_the_disk(self):
        for path in ("/api/runs/..%2f..%2f..%2fetc", "/api/runs/r-zzzz", "/api/runs/r-00000000",
                     "/api/runs/r-00000000/files/f0001/preview"):
            self.assertEqual(self.get(path).status_code, 404, path)
        self.assertEqual(self.post("/api/quarantine/..%2f..%2fetc/restore").status_code, 404)


class TestScanning(WebBase):
    def test_status(self):
        s = self.get("/api/status").json()
        self.assertTrue(s["model_reachable"])
        self.assertEqual(s["models_missing"], [])
        self.assertTrue(s["offline_line"].startswith("Offline"))

    def test_scan_shows_groups_reasons_and_progress(self):
        run = self.scan()
        self.assertEqual(run["state"], "APPROVE")
        self.assertTrue(run["can_move"])
        self.assertEqual(run["summary"]["deletable"], 2)
        self.assertEqual(run["summary"]["sensitive"], 2)
        self.assertTrue(any("batch 1 of 1 done" in x for x in run["progress"]))
        self.assertEqual(self.file(run, "report (1).pdf")["reason"], "exact copy of report.pdf")
        self.assertIn(run["run_id"], [r["run_id"] for r in self.get("/api/runs").json()["runs"]])

    def test_refused_folder_is_not_read_and_makes_no_run(self):
        target = Path(self.service.profile.protected[0].replace("/**", ""))
        with mock.patch.object(Path, "is_dir", lambda self: True):
            r = self.post("/api/scan", {"folder": str(target)})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["kind"], "refused")
        self.assertIn("will not scan", r.json()["error"])
        self.assertFalse(Path(self.cfg.paths.runs_dir).exists())

    def test_missing_folder(self):
        self.assertEqual(self.post("/api/scan", {"folder": str(self.tmp / "nope")}).status_code, 400)
        self.assertEqual(self.post("/api/scan", {"folder": ""}).status_code, 400)

    def test_only_one_pipeline_at_a_time(self):
        started, release = threading.Event(), threading.Event()

        def slow(*a, **k):
            started.set()
            release.wait(5)
            return model(*a, **k)
        self.h.client.auto = slow
        r = self.post("/api/scan", {"folder": str(self.root)})
        self.assertTrue(started.wait(5))
        self.assertEqual(self.post("/api/scan", {"folder": str(self.root)}).status_code, 409)
        release.set()
        self.h.client.auto = model
        self.wait(r.json()["run_id"])

    def test_ollama_down_then_resume(self):
        self.h.client.auto = lambda *a, **k: (_ for _ in ()).throw(LLMConnectionError("down"))
        run = self.scan()
        self.assertEqual(run["state"], "FAILED")
        self.assertEqual(run["error"], "LLMConnectionError")
        self.assertTrue(run["can_resume"])
        self.assertFalse(run["can_move"])
        self.h.client.auto = model
        self.assertEqual(self.post(f"/api/runs/{run['run_id']}/resume").status_code, 200)
        self.assertEqual(self.wait(run["run_id"])["state"], "APPROVE")

    def test_dry_run_can_never_move(self):
        run = self.scan(dry_run=True)
        self.assertEqual(run["state"], "DONE")
        self.assertFalse(run["can_move"])
        r = self.post(f"/api/runs/{run['run_id']}/move",
                      {"file_ids": self.ids(run, "setup_zoom.exe"), "confirm": "MOVE"})
        self.assertEqual(r.status_code, 409)
        self.assertTrue((self.root / "setup_zoom.exe").exists())


class TestFileManagement(WebBase):
    def move(self, run, ids, confirm="MOVE", sensitive=""):
        return self.post(f"/api/runs/{run['run_id']}/move",
                         {"file_ids": ids, "confirm": confirm, "sensitive_confirm": sensitive})

    def test_move_needs_the_typed_word(self):
        run = self.scan()
        ids = self.ids(run, "setup_zoom.exe")
        for word in ("", "move", "yes", "MOVE "):
            r = self.move(run, ids, confirm=word)
            self.assertEqual(r.status_code, 400, word)
        self.assertTrue((self.root / "setup_zoom.exe").exists())
        self.assertEqual(self.get(f"/api/runs/{run['run_id']}").json()["state"], "APPROVE")

    def test_move_and_restore(self):
        run = self.scan()
        r = self.move(run, self.ids(run, "setup_zoom.exe", "report (1).pdf"))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["moved"], 2)
        self.assertFalse((self.root / "setup_zoom.exe").exists())
        after = self.get(f"/api/runs/{run['run_id']}").json()
        self.assertFalse(after["can_move"])
        batch = r.json()["batch_id"]
        self.assertEqual(self.file(after, "setup_zoom.exe")["batch_id"], batch)
        q = self.get("/api/quarantine").json()
        self.assertEqual([b["batch_id"] for b in q["batches"]], [batch])
        self.assertTrue(q["batches"][0]["can_restore"])
        self.assertEqual(self.post(f"/api/quarantine/{batch}/restore").json()["restored"], 2)
        self.assertTrue((self.root / "setup_zoom.exe").exists())
        q = self.get("/api/quarantine").json()
        self.assertFalse(q["batches"][0]["can_restore"])

    def test_keep_files_cannot_be_moved(self):
        run = self.scan()
        r = self.move(run, self.ids(run, "cv.pdf"))
        self.assertEqual(r.status_code, 403)
        self.assertTrue((self.root / "cv.pdf").exists())

    def test_one_bad_id_stops_the_whole_move(self):
        run = self.scan()
        r = self.move(run, self.ids(run, "setup_zoom.exe", "cv.pdf"))
        self.assertEqual(r.status_code, 403)
        self.assertTrue((self.root / "setup_zoom.exe").exists())

    def test_invalid_selection(self):
        run = self.scan()
        for ids in ([], None, "f0001", [1], ["../../etc/passwd"]):
            self.assertEqual(self.move(run, ids).status_code, 400, ids)

    def test_sensitive_needs_the_second_word_and_is_recorded(self):
        run = self.scan()
        f = self.file(run, "passport (1).txt")
        self.assertEqual(f["group"], "sensitive")
        self.assertEqual(f["label"], "keep")                      # the UAT-05 case
        self.assertTrue(f["selectable"])
        r = self.move(run, [f["file_id"]])
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["kind"], "needs_sensitive")
        self.assertTrue((self.root / "passport (1).txt").exists())
        r = self.move(run, [f["file_id"]], sensitive="SENSITIVE")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["sensitive_confirmed"], 1)
        state = json.loads((Path(self.cfg.paths.runs_dir) / run["run_id"] / "state.json").read_text("utf-8"))
        self.assertEqual(state["sensitive_confirmed"], [f["file_id"]])
        self.assertTrue((self.root / "passport.txt").exists())

    def test_file_edited_after_scan_is_reported_not_moved(self):
        run = self.scan()
        target = self.root / "setup_zoom.exe"
        with open(target, "ab") as fh:
            fh.write(b"edited")
        r = self.move(run, self.ids(run, "setup_zoom.exe", "report (1).pdf")).json()
        self.assertEqual(r["moved"], 1)
        self.assertEqual(r["skipped"][0]["name"], "setup_zoom.exe")
        self.assertIn("changed after the scan", r["skipped"][0]["why"])
        self.assertTrue(target.exists())

    def test_preview(self):
        run = self.scan()
        rid, fid = run["run_id"], self.ids(run, "passport.txt")[0]
        self.assertIn("AA1234567", self.get(f"/api/runs/{rid}/files/{fid}/preview").json()["text"])
        other = self.ids(run, "mystery.bin")[0]
        self.assertIsNone(self.get(f"/api/runs/{rid}/files/{other}/preview").json()["text"])

    def test_preview_of_a_moved_file(self):
        run = self.scan()
        fid = self.ids(run, "setup_zoom.exe")[0]
        self.move(run, [fid])
        r = self.get(f"/api/runs/{run['run_id']}/files/{fid}/preview")
        self.assertEqual((r.status_code, r.json()["kind"]), (404, "gone"))

    def test_symlink_swapped_in_after_scan_is_not_followed(self):
        run = self.scan()
        secret = self.tmp / "outside.txt"
        secret.write_text("TOP-SECRET-TEXT", encoding="utf-8")
        target = self.root / "passport.txt"
        target.unlink()
        target.symlink_to(secret)
        r = self.get(f"/api/runs/{run['run_id']}/files/{self.ids(run, 'passport.txt')[0]}/preview")
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("TOP-SECRET-TEXT", r.text)

    def test_reveal_shows_but_never_runs_the_file(self):
        run = self.scan()
        with mock.patch("cleanguard.web.service.subprocess.Popen") as popen:
            r = self.post(f"/api/runs/{run['run_id']}/files/{self.ids(run, 'setup_zoom.exe')[0]}/reveal")
        self.assertEqual(r.status_code, 200)
        cmd = popen.call_args[0][0]
        self.assertTrue(cmd[:2] == ["open", "-R"] or cmd[0] in ("explorer", "xdg-open"), cmd)

    def test_browse_lists_folders_only_and_marks_refused_ones(self):
        (self.root / "sub").mkdir()
        d = self.get("/api/browse", params={"path": str(self.root)}).json()
        self.assertEqual([f["name"] for f in d["folders"]], ["sub"])          # no file names
        self.assertIsNone(d["folders"][0]["refused"])
        self.assertEqual(self.get("/api/browse", params={"path": str(self.tmp / "nope")}).status_code, 404)


def tool_call(name, **args):
    return {"tool_calls": [{"function": {"name": name, "arguments": args}}]}


class TestChat(WebBase):
    def chat(self, run, *outputs, message="Which files can go?"):
        self.h.client.outputs = list(outputs)
        return self.post("/api/chat", {"message": message, "run_id": run["run_id"] if run else None})

    def test_answers_using_a_tool(self):
        run = self.scan()
        r = self.chat(run, tool_call("list_files", group="deletable"), "Two installers can go.").json()
        self.assertEqual(r["reply"], "Two installers can go.")
        self.assertEqual(r["tools_used"], ["list_files"])
        tools = [m for m in self.h.client.requests[-1]["messages"] if m["role"] == "tool"]
        self.assertEqual(len(tools), 2)                           # snapshot + the model's own call
        self.assertIn("setup_zoom.exe", tools[-1]["content"])
        self.assertNotIn("cv.pdf", tools[-1]["content"])          # the group it asked for

    def test_file_names_arrive_as_tool_results_not_in_the_system_prompt(self):
        run = self.scan()
        self.chat(run, "ok")
        msgs = self.h.client.requests[-1]["messages"]
        self.assertEqual(msgs[0]["role"], "system")
        self.assertNotIn("setup_zoom", msgs[0]["content"])        # untrusted names stay out of it
        self.assertEqual([m["role"] for m in msgs], ["system", "assistant", "tool", "user"])
        self.assertIn("setup_zoom.exe", msgs[2]["content"])

    def test_context_and_history_reach_the_model(self):
        run = self.scan()
        self.chat(run, "First answer.")
        self.chat(run, "Second answer.", message="And then?")
        msgs = self.h.client.requests[-1]["messages"]
        self.assertIn("2 deletable", msgs[0]["content"])
        said = [m["content"] for m in msgs if m["role"] in ("user", "assistant") and m["content"]]
        self.assertEqual(said, ["Which files can go?", "First answer.", "And then?"])

    def test_markdown_marks_are_removed_for_the_plain_text_page(self):
        self.assertEqual(self.chat(None, "See `notes.txt` and **this**.").json()["reply"], "See notes.txt and this.")

    def test_chat_works_with_no_scan(self):
        r = self.chat(None, "Choose a folder first.")
        self.assertEqual(r.json()["reply"], "Choose a folder first.")
        self.assertIn("No scan is open", self.h.client.requests[-1]["messages"][0]["content"])

    def test_chat_cannot_move_files_even_if_the_model_tries(self):
        run = self.scan()
        ids = self.ids(run, "setup_zoom.exe")
        attempts = [tool_call("quarantine_files", file_ids=ids, approval_token="made-up"),
                    tool_call("delete_permanent", file_ids=ids),
                    tool_call("restore_batch", batch_id="q-20260101-000000-abcd"), "Done."]
        r = self.chat(run, *attempts).json()
        self.assertEqual(r["actions"], [])
        self.assertTrue((self.root / "setup_zoom.exe").exists())
        self.assertFalse(self.service.profile.quarantine_dir.exists())
        self.assertEqual(self.get(f"/api/runs/{run['run_id']}").json()["state"], "APPROVE")
        msgs = [m["content"] for m in self.h.client.requests[-1]["messages"] if m["role"] == "tool"][1:]
        self.assertEqual(len(msgs), 3)                            # after the snapshot
        self.assertTrue(all("not available in chat" in m for m in msgs), msgs)

    def test_pipeline_read_tools_are_not_callable_from_chat(self):
        run = self.scan()
        before = json.loads((Path(self.cfg.paths.runs_dir) / run["run_id"] / "files.json").read_text("utf-8"))
        self.chat(run, tool_call("scan_folder"), tool_call("read_snippet", file_id="f0001"), "No.")
        msgs = [m["content"] for m in self.h.client.requests[-1]["messages"] if m["role"] == "tool"][1:]
        self.assertTrue(msgs and all("not available in chat" in m for m in msgs), msgs)
        after = json.loads((Path(self.cfg.paths.runs_dir) / run["run_id"] / "files.json").read_text("utf-8"))
        self.assertEqual(before, after)

    def test_offered_tools_are_read_only_and_exactly_the_chat_list(self):
        run = self.scan()
        self.chat(run, "ok")
        names = {t["function"]["name"] for t in self.h.client.requests[-1]["tools"]}
        self.assertEqual(names, {"scan_summary", "list_files", "file_details", "propose_selection", "propose_scan"})
        from harness.tools import TOOLS
        self.assertTrue(all(TOOLS[n].permission == "read" for n in names))

    def test_suggestions_never_include_sensitive_or_keep_files(self):
        run = self.scan()
        ids = self.ids(run, "setup_zoom.exe", "mystery.bin", "passport (1).txt", "cv.pdf")
        r = self.chat(run, tool_call("propose_selection", file_ids=ids + ["f9999"]), "Suggested.").json()
        self.assertEqual(r["actions"], [{"type": "select", "file_ids": ids[:2]}])
        tool_msg = [m for m in self.h.client.requests[-1]["messages"] if m["role"] == "tool"][-1]
        self.assertIn('"left_out": 3', tool_msg["content"])

    def test_a_sensitive_file_marked_review_is_not_suggested_either(self):
        make_file(self.root, "statement.bin", os.urandom(70), 300)
        run = self.scan()
        f = self.file(run, "statement.bin")
        self.assertEqual((f["label"], f["sensitive"], f["selectable"]), ("review", True, True))
        r = self.chat(run, tool_call("propose_selection", file_ids=[f["file_id"]]), "Suggested.").json()
        self.assertEqual(r["actions"], [])

    def test_a_suggestion_moves_nothing(self):
        run = self.scan()
        ids = self.ids(run, "setup_zoom.exe")
        self.chat(run, tool_call("propose_selection", file_ids=ids), "Suggested.")
        self.assertTrue((self.root / "setup_zoom.exe").exists())

    def test_propose_scan_starts_nothing_and_respects_refusal(self):
        r = self.chat(None, tool_call("propose_scan", folder=str(self.root)), "Want me to?").json()
        self.assertEqual(r["actions"], [{"type": "scan", "folder": str(self.root)}])
        self.assertFalse(Path(self.cfg.paths.runs_dir).exists())
        missing = self.chat(None, tool_call("propose_scan", folder=str(self.tmp / "nope")), "No.").json()
        self.assertEqual(missing["actions"], [])

    def test_log_holds_no_names_questions_or_answers(self):
        run = self.scan()
        self.chat(run, tool_call("list_files", contains="passport"), tool_call("file_details", file_id="f0001"),
                  "The passport_scan answer.", message="Tell me about my passport secrets")
        log = self.h.log.path.read_text(encoding="utf-8")
        for leak in ("passport", "Tell me", "setup_zoom", str(self.root)):
            self.assertNotIn(leak, log, leak)
        self.assertIn('"source": "chat"', log)

    def test_model_down_is_a_clear_error_and_files_still_work(self):
        run = self.scan()
        self.h.client.auto = lambda *a, **k: (_ for _ in ()).throw(LLMConnectionError("down"))
        r = self.chat(run)
        self.assertEqual((r.status_code, r.json()["kind"]), (503, "model_down"))
        self.assertIn("Ollama", r.json()["error"])
        ok = self.post(f"/api/runs/{run['run_id']}/move",
                       {"file_ids": self.ids(run, "setup_zoom.exe"), "confirm": "MOVE"})
        self.assertEqual(ok.status_code, 200)

    def test_endless_tool_calls_stop(self):
        run = self.scan()
        r = self.chat(run, *[tool_call("scan_summary")] * 3, "Enough.").json()
        self.assertEqual(r["reply"], "Enough.")
        self.assertEqual(len(r["tools_used"]), 3)

    def test_message_limits(self):
        self.assertEqual(self.post("/api/chat", {"message": ""}).status_code, 400)
        self.assertEqual(self.post("/api/chat", {"message": "x" * 2001}).status_code, 400)

    def test_reset_forgets_the_conversation(self):
        run = self.scan()
        self.chat(run, "First.")
        self.post("/api/chat/reset", {"run_id": run["run_id"]})
        self.chat(run, "Second.", message="New question")
        said = [m["content"] for m in self.h.client.requests[-1]["messages"]
                if m["role"] in ("user", "assistant") and m["content"]]
        self.assertEqual(said, ["New question"])


if __name__ == "__main__":
    unittest.main()
