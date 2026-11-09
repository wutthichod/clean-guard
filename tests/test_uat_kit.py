"""UAT regression (offline): build the real UAT folders from data/test_set.jsonl, drive every
task through CleanGuard with a fake model, and grade it with check_uat.evaluate.

- oracle model: answers the first acceptable label. Every automatic check of the UAT plan must
  pass, which proves the kit and CleanGuard fit together.
- hostile model: repeats the failures in the UAT report. It marks everything deletable and
  nothing sensitive, reads nothing, and writes reasons that claim things it never saw. Issues 1,
  2 and 4 of the report must not come back, from the rules alone.

A real model can still be wrong in other ways, so this does not replace re-running the UAT.
"""
import io
import json
import random
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _cg_util import ROOT, _files_in, make_harness, profile, settings, tmpdir  # noqa: E402

from harness import LLMConnectionError  # noqa: E402

import check_uat  # noqa: E402  (ROOT is on sys.path)
import make_uat_folders  # noqa: E402
from cleanguard import cli, run_context  # noqa: E402
from cleanguard.platform import current_os, load_profile  # noqa: E402
from cleanguard.report import groups  # noqa: E402
from cleanguard.state_machine import CleanGuardRun, load_run, new_run  # noqa: E402

TESTS = ROOT / "data" / "test_set.jsonl"
OS = current_os() if current_os() in ("macos", "windows") else "macos"
PROTECTED = {"macos": "~/Library", "windows": "C:/Windows", "linux": "/usr"}[current_os()]


def specs_by_name(tasks) -> dict:
    out = {}
    for t in tasks:
        for s in t.get("files", []):
            out[Path(s["path"].replace("{inst}", make_uat_folders.INSTALLER[OS])).name] = s
    return out


def fake_model(spec, hostile=False):
    def reply(model, messages, schema=None, tools=None, **kw):
        if tools:
            return "DONE"                                       # never reads: the sweep must cope
        is_privacy = "label" not in json.dumps(schema or {})
        out = []
        for f in _files_in(messages):
            s = spec[f["name"]]
            sens = False if hostile else s["sensitive"]
            v = {"file_id": f["file_id"], "sensitive": sens,
                 "sensitive_type": "personal" if sens else "none",
                 "reason": "It is empty and already extracted." if hostile else "Fake model answer."}
            if not is_privacy:
                v["label"] = "deletable" if hostile else s["acceptable"][0]
            out.append(v)
        return json.dumps({"verdicts": out})
    return reply


class UATBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.tasks = check_uat.load_tasks(TESTS)
        self.folders = self.tmp / "uat_folders"
        self.folders.mkdir()
        rng = random.Random(4)
        for t in self.tasks:
            if t.get("files"):
                make_uat_folders.build(t, self.folders, OS, rng)
        self.cfg = settings(self.tmp)
        self.prof = profile(self.tmp)
        self.spec = specs_by_name(self.tasks)
        self.addCleanup(run_context.set_active, None)

    def task(self, tid):
        return check_uat.find_task(self.tasks, tid)

    def scan(self, folder, h, dry_run=False, progress=None):
        run = new_run(self.folders / folder, self.cfg, profile=self.prof, dry_run=dry_run)
        state = CleanGuardRun(h, run, self.cfg, progress=progress).until_pause()
        return run, state

    def grade(self, tid, run=None, targets=None):
        rdir = (self.tmp / "runs" / run.run_id) if run else None
        return check_uat.evaluate(self.task(tid), self.tasks, self.folders, rdir, targets,
                                  self.tmp / "runs")

    def assertPasses(self, res):
        failed = [f"{c['name']} ({c['detail']})" for c in res["checks"] if not c["ok"]]
        self.assertTrue(res["checks"], f"{res['task']}: no automatic checks ran")
        self.assertEqual(failed, [], res["task"])

    def approve(self, run, h, sensitive="", out=None):
        answers = {"Move which": "all", "Add review": "", "Add sensitive": sensitive,
                   "Type SENSITIVE": "SENSITIVE", "Type MOVE": "MOVE"}

        def ask(prompt):
            return next(v for k, v in answers.items() if prompt.startswith(k))
        return cli.approve(h, load_run(run.run_id, self.cfg), self.cfg, ask=ask,
                           say=(out.append if out is not None else lambda *_: None))


class TestTestSet(UATBase):
    def test_folders_match_the_plan(self):
        manifests = sorted(self.folders.glob("*.manifest.json"))
        self.assertEqual(len(manifests), 9)
        self.assertEqual(sum(len(json.loads(m.read_text(encoding="utf-8"))) for m in manifests), 107)
        self.assertEqual(sum(s["sensitive"] for t in self.tasks for s in t.get("files", [])), 15)
        self.assertEqual(len(self.tasks), 13)


class TestOracleModel(UATBase):
    """A model that is always right: every automatic UAT check passes."""

    def h(self):
        return make_harness(self, auto=fake_model(self.spec))

    def test_uat01_02_approve_then_restore_the_named_file(self):
        h = self.h()
        run, state = self.scan("uat01", h)
        self.assertEqual(state, "APPROVE")
        q = self.approve(run, h)
        names = [run.records[f].name for f in q["moved"]]
        self.assertTrue(any(n.startswith("setup_zoom") for n in names), names)   # report limitation
        self.assertPasses(self.grade("T01", run))
        res = cli.restore_flow(h, self.cfg, q["batch_id"], self.prof.quarantine_dir)
        self.assertTrue(res["ok"], res)
        self.assertPasses(self.grade("T02"))

    def test_label_tasks(self):
        for tid in ("T03", "T04", "T07", "T11", "T12"):
            with self.subTest(tid):
                run, state = self.scan(self.task(tid)["folder"], self.h())
                self.assertEqual(state, "APPROVE")
                self.assertPasses(self.grade(tid, run))

    def test_uat05_sensitive_duplicate_gets_the_extra_warning(self):
        h = self.h()
        run, _ = self.scan("uat04", h)
        g = groups(run)
        ordered = g["deletable"] + g["review"] + g["sensitive"]
        num = next(i for i, (r, _) in enumerate(ordered, 1) if r.name == "passport_scan (1).pdf")
        rec, dec = ordered[num - 1]
        self.assertEqual(dec.label, "keep")                       # the case that was unreachable
        self.assertIn("Exact copy of passport_scan.pdf", dec.reason)
        out = []
        q = self.approve(run, h, sensitive=str(num), out=out)
        self.assertTrue(any(line.startswith("WARNING") for line in out), out)
        self.assertEqual([run.records[f].name for f in q["moved"]], ["passport_scan (1).pdf"])
        self.assertTrue((self.folders / "uat04" / "passport_scan.pdf").exists())
        again = load_run(run.run_id, self.cfg)
        self.assertEqual(again.sensitive_confirmed, [rec.file_id])    # conscious choice recorded
        log = [json.loads(x) for x in h.log.path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["sensitive_confirmed"] for e in log if e["event"] == "quarantine_batch"], [1])
        self.assertPasses(self.grade("T05"))
        self.assertPasses(self.grade("T04", run))

    def test_uat05_without_the_word_sensitive_nothing_moves(self):
        h = self.h()
        run, _ = self.scan("uat04", h)
        n = len(groups(run)["deletable"]) + len(groups(run)["review"]) + 1
        answers = iter([str(n), "no"])
        res = cli.approve(h, load_run(run.run_id, self.cfg), self.cfg,
                          ask=lambda p: next(answers), say=lambda *_: None)
        self.assertIsNone(res)
        self.assertEqual(len(list((self.folders / "uat04").iterdir())), 7)

    def test_uat06_ollama_quits_after_batch_1_then_resume(self):
        h = self.h()
        oracle = h.client.auto
        lines = []

        def progress(msg):
            lines.append(msg)
            if msg.startswith("batch 1 of") and "done" in msg:     # the observer quits Ollama
                h.client.auto = lambda *a, **k: (_ for _ in ()).throw(LLMConnectionError("down"))
        run, state = self.scan("uat06", h, progress=progress)
        self.assertEqual(state, "FAILED")
        self.assertEqual(run.failed_from, "CLASSIFY")              # stopped at batch 2: verified
        self.assertTrue(any("batch 1 of 2 done" in x for x in lines), lines)
        self.assertFalse(self.prof.quarantine_dir.exists())
        out = io.StringIO()
        with redirect_stdout(out):
            cli._after(run, self.cfg, state)
        self.assertIn("could not connect to the local model", out.getvalue())
        self.assertIn(f"cleanguard resume {run.run_id}", out.getvalue())
        h.client.auto = oracle                                     # Ollama is back
        again = load_run(run.run_id, self.cfg)
        self.assertEqual(CleanGuardRun(h, again, self.cfg).resume(), "APPROVE")
        self.assertPasses(self.grade("T06", again))

    def test_uat08_system_and_cloud_folders_refused_before_reading(self):
        targets = {"{protected_root}": Path(PROTECTED).expanduser(),
                   "{cloud_root}": Path(load_profile().sync_roots[0].replace("/**", "").replace("*", ""))}
        for tid in ("T08", "T09"):
            with self.subTest(tid):
                self.assertPasses(self.grade(tid, targets=targets))
        self.assertIn("cloud", load_profile().refusal_reason(targets["{cloud_root}"]))
        if targets["{protected_root}"].is_dir():
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(["scan", str(targets["{protected_root}"])])
            self.assertEqual(code, 2)
            self.assertIn("will not scan", out.getvalue())
            self.assertIn("Nothing was read or moved", out.getvalue())

    def test_uat09_file_edited_after_scan_is_skipped(self):
        h = self.h()
        run, _ = self.scan("uat09", h)
        edited = self.folders / "uat09" / "meeting_2023 (1).txt"
        with open(edited, "a", encoding="utf-8") as f:
            f.write("\nNote added after the scan.\n")
        out = []
        self.approve(run, h, out=out)
        self.assertTrue(edited.exists())
        self.assertTrue(any("NOT moved: meeting_2023 (1).txt" in x for x in out), out)
        self.assertPasses(self.grade("T10", run))

    def test_uat12_field_test_dry_run(self):
        run, state = self.scan("uat12", self.h(), dry_run=True)
        self.assertEqual(state, "DONE")
        self.assertPasses(self.grade("T13", run))


class TestHostileModel(UATBase):
    """The report's failures, on purpose: all deletable, nothing sensitive, ungrounded reasons."""

    def run_task(self, t):
        h = make_harness(self, auto=fake_model(self.spec, hostile=True))
        run, _ = self.scan(t["folder"], h, dry_run=True)
        return run, self.grade(t["id"], run)

    def test_issue_1_no_unacceptable_deletable_label_in_any_task(self):
        for t in self.tasks:
            if t["expected"].get("labels"):
                with self.subTest(t["id"]):
                    _, res = self.run_task(t)
                    bad = [c for c in res["checks"] if not c["ok"]]
                    self.assertEqual(bad, [])
                    self.assertEqual(res["acceptable"], res["labeled"])

    def test_issue_1_the_three_named_files_are_review(self):
        run, _ = self.run_task(self.task("T11"))
        by = {r.name: run.decisions[f] for f, r in run.records.items()}
        for name in ("untitled.pdf", "New Document.txt"):
            self.assertEqual(by[name].label, "review", name)
            self.assertEqual(by[name].decided_by, "evidence")
        run, _ = self.run_task(self.task("T12"))
        by = {r.name: run.decisions[f] for f, r in run.records.items()}
        self.assertEqual(by["old_backup.zip"].label, "review")
        self.assertIn("backup", by["old_backup.zip"].reason)
        self.assertEqual(by[f"setup_teams{make_uat_folders.INSTALLER[OS]}"].label, "deletable")

    def test_issue_2_every_sensitive_file_is_flagged(self):
        # report targets: UAT-04 5 of 5, UAT-12 7 of 7
        for tid, want in (("T04", 5), ("T13", 7)):
            with self.subTest(tid):
                _, res = self.run_task(self.task(tid))
                self.assertEqual((res["sensitive_flagged"], res["sensitive_total"]), (want, want))
                self.assertEqual(res["sensitive_deletable"], 0)

    def test_issue_4_reasons_do_not_claim_what_was_not_seen(self):
        run, _ = self.run_task(self.task("T13"))
        for f, d in run.decisions.items():
            if d.decided_by in ("llm_fast", "llm_reasoning") and f not in run.shown:
                self.assertIn("not opened", d.reason.lower(), run.records[f].name)
                self.assertNotIn("empty", d.reason.lower(), run.records[f].name)


if __name__ == "__main__":
    unittest.main()
