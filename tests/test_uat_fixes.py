"""Unit tests for the fixes from the UAT report: evidence rule, sweep, reasons, token, flow."""
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
from _cg_util import (auto_reply, make_file, make_harness, make_run, profile, record,  # noqa: E402
                      settings, tmpdir, verdicts)

from harness import execute  # noqa: E402
from harness.logger import JsonlLogger, redact  # noqa: E402

from cleanguard import cli  # noqa: E402
from cleanguard.agent import classify_batch  # noqa: E402
from cleanguard.evidence import (apply_evidence, deletable_evidence, ground_reasons,  # noqa: E402
                                 is_generic_name, usable_chars)
from cleanguard.records import Decision  # noqa: E402
from cleanguard.signals import find_signals  # noqa: E402
from cleanguard.state_machine import CleanGuardRun, load_run, new_run  # noqa: E402
from cleanguard.sweep import sweep_signals  # noqa: E402


class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.cfg = settings(self.tmp)

    def evidence(self, *recs, read=None):
        run = make_run(self.tmp, list(recs))
        run.read_chars = read or {}
        return {r.name: deletable_evidence(r, run, self.cfg) for r in recs}

    def test_positive_reasons(self):
        got = self.evidence(record("f0001", "a/setup_zoom.exe"), record("f0002", "a/x.dmg"),
                            record("f0003", "a/report (1).pdf", dup_of="f0009"),
                            record("f0004", "a/movie.mp4.crdownload", days=45))
        self.assertEqual(got["setup_zoom.exe"], "installer")
        self.assertEqual(got["report (1).pdf"], "exact duplicate")
        self.assertEqual(got["movie.mp4.crdownload"], "unfinished download")

    def test_no_evidence(self):
        got = self.evidence(record("f0001", "a/untitled.pdf"), record("f0002", "a/New Document.txt"),
                            record("f0003", "a/old_backup.zip", days=900), record("f0004", "a/data.zip"),
                            record("f0005", "a/IMG_2041.HEIC"), record("f0006", "a/family_photos.zip"),
                            record("f0007", "a/setup_backup_tool.exe"),   # keep word beats installer
                            record("f0008", "a/สำรองข้อมูล.zip"))
        self.assertEqual(set(got.values()), {None}, got)

    def test_draft_needs_read_text_and_a_final_with_the_same_name(self):
        draft, final = record("f0001", "a/essay_draft2.docx"), record("f0002", "a/essay_final.docx")
        self.assertIsNotNone(self.evidence(draft, final, read={"f0001": 40})["essay_draft2.docx"])
        self.assertIsNone(self.evidence(draft, final)["essay_draft2.docx"])          # not read
        self.assertIsNone(self.evidence(draft, final, read={"f0001": 4})["essay_draft2.docx"])  # near empty
        self.assertIsNone(self.evidence(draft, read={"f0001": 40})["essay_draft2.docx"])  # no final
        other = record("f0003", "a/report_final.docx")
        self.assertIsNone(self.evidence(draft, other, read={"f0001": 40})["essay_draft2.docx"])
        elsewhere = record("f0004", "b/essay_final.docx")
        self.assertIsNone(self.evidence(draft, elsewhere, read={"f0001": 40})["essay_draft2.docx"])
        thai = record("f0005", "a/รายงาน_ฉบับร่าง.docx")
        thai_final = record("f0006", "a/รายงาน_final.docx")
        self.assertIsNotNone(self.evidence(thai, thai_final, read={"f0005": 40})["รายงาน_ฉบับร่าง.docx"])

    def test_image_only_pdf_counts_as_no_text(self):
        self.assertEqual(usable_chars("[no extractable text: scanned PDF or image]"), 0)
        self.assertEqual(usable_chars("  hello  "), 5)

    def test_downgrade_is_per_file_and_logged_without_names(self):
        h = make_harness(self)
        rec = record("f0001", "a/old_backup.zip")
        run = make_run(self.tmp, [rec])
        d = Decision("f0001", "deletable", False, "none", "Old file.", "llm_fast")
        self.assertTrue(apply_evidence(d, rec, run, self.cfg, h.log))
        self.assertEqual((d.label, d.decided_by), ("review", "evidence"))
        log = h.log.path.read_text(encoding="utf-8")
        self.assertIn("evidence_downgrade", log)
        self.assertNotIn("old_backup", log)

    def test_batch_keeps_good_labels_when_one_has_no_evidence(self):
        h = make_harness(self, [verdicts(("f0001", "deletable"), ("f0002", "deletable"), ("f0003", "keep"))])
        recs = [record("f0001", "a/setup.exe"), record("f0002", "a/untitled.bin"), record("f0003", "a/cv.bin")]
        make_run(self.tmp, recs)
        out = {d.file_id: d for d in classify_batch(h, recs, settings(self.tmp), "r-test")}
        self.assertEqual(out["f0001"].label, "deletable")
        self.assertEqual(out["f0002"].label, "review")
        self.assertEqual(out["f0003"].label, "keep")
        self.assertEqual(len(h.client.requests), 1)              # no extra model call


class TestSweep(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.root = self.tmp / "folder"
        self.cfg = settings(self.tmp)

    def sweep(self):
        recs = []
        for i, p in enumerate(sorted(self.root.rglob("*")), 1):
            if p.is_file():
                rel = p.relative_to(self.root).as_posix()
                recs.append(record(f"f{i:04d}", rel, size=p.stat().st_size, root=self.root))
        run = make_run(self.tmp, recs, root=self.root)
        return run, sweep_signals(run, self.cfg), {r.name: r.file_id for r in recs}

    def test_private_text_is_found_and_plain_text_is_not_kept(self):
        make_file(self.root, "notes.txt", "Name: Somchai. National ID: 1-2345-67890-12-1")
        make_file(self.root, "report.txt", "Budget summary and event list for the photography club.")
        run, info, ids = self.sweep()
        self.assertEqual((info["read"], info["hits"]), (2, 1))
        self.assertIn(ids["notes.txt"], run.snippets)            # privacy hit, and a generic name
        self.assertNotIn(ids["report.txt"], run.snippets)
        self.assertGreater(run.read_chars[ids["report.txt"]], 30)  # counted, text not kept

    def test_big_and_unsupported_files_are_skipped(self):
        make_file(self.root, "big.txt", "a" * (2 * 1024 * 1024 + 1))
        make_file(self.root, "photo.heic", b"\x00" * 100)
        _, info, _ = self.sweep()
        self.assertEqual(info["read"], 0)

    def test_generic_names(self):
        for n in ("scan_001.pdf", "document (3).docx", "notes.txt", "untitled.pdf", "New Document.txt",
                  "file.bin", "data.zip", "IMG_2041.HEIC", "เอกสาร.pdf"):
            self.assertTrue(is_generic_name(n), n)
        for n in ("report_2024.pdf", "setup_zoom.exe", "essay_final.docx", "passport_scan.pdf"):
            self.assertFalse(is_generic_name(n), n)

    def test_keyword_must_start_a_word_in_text_but_not_in_a_name(self):
        self.assertEqual(find_signals("", "Python syntax and grammar"), [])
        self.assertIn("kw:financial", find_signals("", "Taxpayer ID on the form"))
        self.assertIn("kw:financial", find_signals("mybank.pdf"))
        self.assertIn("kw:financial", find_signals("", "ใบแจ้งเงินเดือนประจำเดือน"))

    def test_swept_text_reaches_the_model_without_a_read_step(self):
        make_file(self.root, "scan_001.txt", "Payslip October. Salary 32,000 THB.", 200)
        h = make_harness(self, auto=auto_reply)
        run = new_run(self.root, self.cfg, profile=profile(self.tmp), dry_run=True)
        CleanGuardRun(h, run, self.cfg).until_pause()
        self.assertFalse(any(r.get("tools") for r in h.client.requests))     # nothing left to read
        sent = json.dumps([r["messages"] for r in h.client.requests], ensure_ascii=False)
        self.assertIn("Payslip October", sent)
        self.assertTrue(next(iter(run.decisions.values())).sensitive)
        log = h.log.path.read_text(encoding="utf-8")
        self.assertNotIn("Payslip", log)
        self.assertNotIn("scan_001", log)


class TestReasons(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)

    def ground(self, reason, shown=False, chars=0, by="llm_fast"):
        run = make_run(self.tmp, [record("f0001")])
        run.decisions = {"f0001": Decision("f0001", "review", False, "none", reason, by)}
        run.shown = ["f0001"] if shown else []
        run.read_chars = {"f0001": chars}
        ground_reasons(run)
        return run.decisions["f0001"].reason

    def test_unread_files_say_not_opened(self):
        self.assertEqual(self.ground("Old installer."), "Old installer. (File not opened.)")

    def test_claims_about_unseen_content_are_removed(self):
        for r in ("The archive is already extracted.", "This file is empty.", "It contains a short note."):
            self.assertEqual(self.ground(r), "Judged from its name, type and age only. (File not opened.)")

    def test_a_reason_cannot_call_read_text_empty(self):
        self.assertNotIn("empty", self.ground("This file is empty.", shown=True, chars=200))

    def test_a_reason_cannot_say_not_opened_for_text_the_model_saw(self):
        got = self.ground("Tax form; not opened.", shown=True, chars=200)
        self.assertNotIn("not opened", got.lower())

    def test_a_reason_cannot_deny_a_final_that_exists(self):
        # seen on the real model in UAT-03: true label, false reason
        draft, final = record("f0001", "a/essay_draft2.docx"), record("f0002", "a/essay_final.docx")
        run = make_run(self.tmp, [draft, final])
        run.decisions = {"f0001": Decision("f0001", "review", False, "none",
                                           "Draft with no final version in the same folder; not opened.", "llm_reasoning")}
        run.shown, run.read_chars = ["f0001"], {"f0001": 40}
        ground_reasons(run)
        self.assertEqual(run.decisions["f0001"].reason, "A draft; a final version with the same name is in this folder.")

    def test_grounded_and_rule_reasons_are_left_alone(self):
        self.assertEqual(self.ground("It is a bank statement.", shown=True, chars=200), "It is a bank statement.")
        self.assertEqual(self.ground("unfinished download", by="rule"), "unfinished download")


class TestTokenNeverLogged(unittest.TestCase):
    def test_redact(self):
        self.assertEqual(redact({"approval_token": "abc", "file_ids": ["f1"]}),
                         {"approval_token": "***", "file_ids": ["f1"]})
        self.assertEqual(redact('{"a": {"API_KEY": "x", "b": 1}}'), {"a": {"API_KEY": "***", "b": 1}})
        self.assertEqual(redact("not json"), "not json")

    def test_logger_masks_it(self):
        tmp = tmpdir(self)
        log = JsonlLogger(tmp / "c.jsonl")
        log.tool_call(run_id="r", name="t", arguments={"approval_token": "s3cret"}, ok=True, duration_s=0.1)
        self.assertNotIn("s3cret", (tmp / "c.jsonl").read_text(encoding="utf-8"))

    def test_a_real_approval_leaves_no_token_in_the_log(self):
        tmp = tmpdir(self)
        root = tmp / "folder"
        make_file(root, "setup_zoom.exe", os.urandom(1000), 400)
        cfg = settings(tmp)
        h = make_harness(self, auto=auto_reply)
        run = new_run(root, cfg, profile=profile(tmp))
        CleanGuardRun(h, run, cfg).until_pause()
        issued = []
        real_issue = cli.GATE.issue

        def spy(*a, **k):
            issued.append(real_issue(*a, **k))
            return issued[-1]
        with mock.patch.object(cli.GATE, "issue", spy):
            answers = iter(["all", "MOVE"])
            cli.approve(h, load_run(run.run_id, cfg), cfg, ask=lambda p: next(answers), say=lambda *_: None)
        self.assertEqual(len(issued), 1)
        log = h.log.path.read_text(encoding="utf-8")
        self.assertIn('"approval_token": "***"', log)            # the call itself is still logged
        self.assertNotIn(issued[0], log)


class TestGuidedFlow(unittest.TestCase):
    def test_offline_line_tells_the_truth(self):
        self.assertTrue(cli.offline_line("http://localhost:11434").startswith("Offline"))
        self.assertTrue(cli.offline_line("http://127.0.0.1:11434").startswith("Offline"))
        self.assertTrue(cli.offline_line("http://gpu.example.com:11434").startswith("WARNING"))

    def test_clean_scans_opens_the_report_and_approves(self):
        tmp = tmpdir(self)
        root = tmp / "folder"
        make_file(root, "setup_zoom.exe", os.urandom(1000), 400)
        cfg = settings(tmp)
        h = make_harness(self, auto=auto_reply)
        with mock.patch.object(cli, "Harness", lambda: h), \
                mock.patch.object(cli, "load_profile", lambda: profile(tmp)), \
                mock.patch("cleanguard.state_machine.load_profile", lambda **k: profile(tmp)), \
                mock.patch.object(cli.webbrowser, "open") as opened, \
                mock.patch("sys.stdin", io.StringIO("all\nMOVE\n")), \
                mock.patch("sys.stdout"):
            code = cli.cmd_clean(mock.Mock(folder=str(root), no_open=False, spec=["folder", "no_open"]), cfg)
        self.assertEqual(code, 0)
        self.assertTrue(opened.call_args[0][0].endswith("report.html"))
        self.assertFalse((root / "setup_zoom.exe").exists())     # moved, after typed MOVE
        self.assertEqual(len(list((tmp / "quarantine").glob("q-*"))), 1)


if __name__ == "__main__":
    unittest.main()
