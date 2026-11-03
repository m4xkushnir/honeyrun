import json
import tempfile
import unittest
from pathlib import Path

from honeyrun import bait, detect
from honeyrun.analyze import analyze
from test_hardening import ex, op


def plan(files, deep=True, **kw):
    with tempfile.TemporaryDirectory() as d:
        for name, body in files.items():
            (Path(d) / name).write_text(body)
        return detect.plan(Path(d), "offline", None, None, 120, 60, deep=deep, **kw)


PKG = json.dumps({"scripts": {"postinstall": "node setup.js", "start": "node s.js"}})


class DeepPlan(unittest.TestCase):
    def test_default_phases_unchanged(self):
        names = [p["name"] for p in plan({"package.json": PKG}, deep=False).phases]
        self.assertEqual(names, ["install", "run", "later-install", "later"])
        self.assertEqual([p["name"] for p in plan({"package.json": PKG}, deep=True).phases][:4], names)

    def test_deep_adds_ci_and_repeat_after_the_clock_phases(self):
        ph = plan({"package.json": PKG}).phases
        self.assertEqual([p["name"] for p in ph][-2:], ["ci", "repeat"])
        ci, rep, run = ph[-2], ph[-1], ph[1]
        self.assertEqual(ci["cmd"], run["cmd"])         # the run phase, not the 45-day replay
        self.assertNotIn("clock", ci)
        self.assertEqual(ci["env"]["CI"], "true")
        self.assertEqual(ci["env"]["GITHUB_ACTIONS"], "true")
        self.assertEqual(ci["env"]["GITHUB_WORKFLOW"], "build")
        self.assertEqual(ci["env"]["RUNNER_OS"], "Linux")
        self.assertEqual(rep["cmd"], f"for i in 1 2 3; do {run['cmd']}; done")
        self.assertEqual(rep["timeout"], run["timeout"] * 2)
        self.assertFalse(rep["mcp"])

    def test_deep_without_later(self):
        ph = plan({"package.json": PKG}, later=False).phases
        self.assertEqual([p["name"] for p in ph], ["install", "run", "ci", "repeat"])

    def test_nothing_to_run_adds_nothing(self):
        self.assertEqual(plan({"README": "x"}).phases, [])


class DeepAnalysis(unittest.TestCase):
    def setUp(self):
        self.baits = bait.generate()

    def go(self, per_phase, net=None, t=None):
        meta = {"phases": [{"name": n, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": [],
                            **({"t0": t[n][0], "t1": t[n][1]} if t else {})} for n in per_phase]}
        tr = {"meta.json": json.dumps(meta).encode(),
              "net.jsonl": "\n".join(json.dumps(r) for r in (net or [])).encode()}
        for n, s in per_phase.items():
            tr[f"{n}.strace"] = s.encode()
        a = analyze(tr, self.baits, "offline")
        return {(f.rule, f.severity) for f in a.findings if f.severity != "info"}, a

    NASTY = ex(5, "/usr/bin/curl", "curl", "http://x.example.net/")

    def test_only_in_ci(self):
        rules, a = self.go({"run": "", "ci": self.NASTY})
        self.assertIn(("ci-triggered", "high"), rules)
        self.assertIn("targets CI secrets", next(f.title for f in a.findings if f.rule == "ci-triggered"))

    def test_same_in_run_and_ci_is_not_ci_only(self):
        rules, _ = self.go({"run": self.NASTY, "ci": self.NASTY})
        self.assertNotIn("ci-triggered", {r for r, _ in rules})

    def test_only_on_repeat(self):
        rules, a = self.go({"run": "", "repeat": self.NASTY})
        self.assertIn(("delayed-activation", "high"), rules)
        self.assertIn("only acts after repeated runs", " ".join(f.title for f in a.findings))

    def test_clock_delay_still_reported(self):
        rules, a = self.go({"run": "", "later": self.NASTY})
        self.assertIn("only acts when the clock is 45 days ahead", " ".join(f.title for f in a.findings))

    def test_incomplete_in_ci_is_not_ci_triggered(self):
        meta = {"phases": [{"name": "run", "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": []},
                           {"name": "ci", "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": [],
                            "evidence_truncated": True}]}
        a = analyze({"meta.json": json.dumps(meta).encode()}, self.baits, "offline")
        self.assertNotIn("ci-triggered", {f.rule for f in a.findings})

    def test_sinkhole_traffic_is_attributed_by_time(self):
        t = {"run": (100.0, 110.0), "ci": (111.0, 120.0)}
        net = [{"kind": "dns", "qname": "webhook.site", "qtype": 1, "t": 115.0}]
        rules, a = self.go({"run": "", "ci": ""}, net=net, t=t)
        self.assertIn(("ci-triggered", "high"), rules)
        self.assertEqual(next(f.phase for f in a.findings if f.rule == "exfil-service"), "ci")

    def test_adjacent_phases_do_not_share_edge_slack(self):
        t = {"later-install": (100.0, 110.0), "ci": (110.1, 120.0)}
        net = [{"kind": "dns", "qname": "webhook.site", "qtype": 1, "t": 111.0}]
        _, a = self.go({"later-install": "", "ci": ""}, net=net, t=t)
        self.assertEqual(next(f.phase for f in a.findings if f.rule == "exfil-service"), "ci")

    def test_untimed_traffic_stays_unattributed(self):
        rules, a = self.go({"run": "", "ci": ""}, net=[{"kind": "dns", "qname": "webhook.site", "qtype": 1, "t": 115.0}])
        self.assertNotIn("ci-triggered", {r for r, _ in rules})
        self.assertIn(("exfil-service", "high"), rules)


if __name__ == "__main__":
    unittest.main()
