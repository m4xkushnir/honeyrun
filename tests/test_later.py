import json
import tempfile
import unittest
from pathlib import Path

from honeyrun import bait, detect
from honeyrun.analyze import analyze, host_expected


def trace(phases, files=None, strace=None):
    out = {"meta.json": json.dumps({"phases": phases}).encode(),
           "files.json": json.dumps(files or {}).encode()}
    for k, v in (strace or {}).items():
        out[f"{k}.strace"] = v.encode()
    return out


def ph(name, **kw):
    return {"name": name, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": [], **kw}


class Plan(unittest.TestCase):
    def repo(self, files):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        for name, body in files.items():
            Path(d.name, name).write_text(body)
        return Path(d.name)

    def names(self, repo, **kw):
        args = dict(network="offline", install=None, run=None, install_timeout=600, run_timeout=30)
        args.update(kw)
        return detect.plan(repo, **args)

    def test_install_hook_replayed_before_run(self):
        r = self.repo({"package.json": json.dumps({"scripts": {"postinstall": "node x.js", "start": "node a"}})})
        p = self.names(r)
        self.assertEqual([x["name"] for x in p.phases], ["install", "run", "later-install", "later"])
        li = p.phases[2]
        self.assertEqual(li["clock"], detect.LATER_CLOCK)
        self.assertEqual(li["timeout"], 180)
        self.assertEqual(li["cmd"], p.phases[0]["cmd"])

    def test_setup_py_replayed(self):
        r = self.repo({"setup.py": "", "main.py": ""})
        self.assertIn("later-install", [x["name"] for x in self.names(r).phases])

    def test_no_hooks_only_run_replayed(self):
        r = self.repo({"package.json": json.dumps({"scripts": {"start": "node a"}})})
        self.assertEqual([x["name"] for x in self.names(r).phases], ["install", "run", "later"])

    def test_custom_install_counts(self):
        r = self.repo({"package.json": json.dumps({"scripts": {"start": "node a"}})})
        p = self.names(r, install="make deps")
        self.assertIn("later-install", [x["name"] for x in p.phases])

    def test_no_later_flag(self):
        r = self.repo({"setup.py": "", "main.py": ""})
        self.assertFalse(any(x["name"].startswith("later") for x in self.names(r, later=False).phases))


class Analysis(unittest.TestCase):
    def test_delayed_rule_for_later_prefix(self):
        hx = lambda s: "".join(f"\\x{b:02x}" for b in s.encode())
        line = f'5 10:00:00.1 openat(AT_FDCWD</workspace>, "{hx("/home/runner/.ssh/id_ed25519")}", O_RDONLY) = 3'
        res = analyze(trace([ph("install"), ph("later-install", clock="+45d", clock_shifted=True)],
                            strace={"later-install": line}), bait.generate(), "offline")
        self.assertTrue(any(f.rule == "delayed-activation" and f.phase == "later-install" for f in res.findings))

    def test_clock_not_shifted_is_incomplete(self):
        res = analyze(trace([ph("run"), ph("later", clock="+45d", clock_shifted=False)]), bait.generate(), "offline")
        self.assertTrue(any(f.rule == "incomplete" and f.severity == "medium" and "clock" in f.title for f in res.findings))
        res = analyze(trace([ph("run"), ph("later", clock="+45d", clock_shifted=True)]), bait.generate(), "offline")
        self.assertFalse(any("clock" in f.title for f in res.findings))


class Hosts(unittest.TestCase):
    def test_probe_host(self):
        for h in ("honeyrun.example.net", "honeyrun.example.net.internal.cloudapp.net",
                  "honeyrun.example.net.lan", "honeyrun.example.net.home.arpa", "HONEYRUN.example.net."):
            self.assertTrue(host_expected(h), h)
        for h in ("honeyrun.example.net.evil.com", "honeyrun.example.net.internal.evil.com",
                  "honeyrun.example.net.local.evil.com", "xhoneyrun.example.net"):
            self.assertFalse(host_expected(h), h)


class SitePackages(unittest.TestCase):
    ELF = "7f454c46"
    SITE = "/home/runner/.local/lib/python3.12/site-packages/"

    def findings(self, name):
        files = {"created": [[self.SITE + name, 100, "0o755", self.ELF]]}
        return analyze(trace([ph("install")], files), bait.generate(), "offline").findings

    def test_extension_modules_exempt(self):
        for n in ("numpy/core/_x.cpython-312-x86_64-linux-gnu.so", "pkg/_y.abi3.so", "pkg/libz.so.1",
                  "pkg/libz.so.1.2.3", "numpy.libs/libopenblas-r0.3.so", "numpy.libs/libgfortran-abc"):
            self.assertEqual([f for f in self.findings(n) if f.rule == "dropped-binary"], [], n)

    def test_other_native_files_flagged(self):
        for n in ("pkg/helper", "pkg/run.exe", "pkg/payload.bin"):
            fs = [f for f in self.findings(n) if f.rule == "dropped-binary"]
            self.assertEqual([f.severity for f in fs], ["medium"], n)
            self.assertIn("native executable inside site-packages", fs[0].title)


if __name__ == "__main__":
    unittest.main()


class LaterOnlyWhenOnlyLater(unittest.TestCase):
    def test_finding_seen_in_run_and_later_is_not_a_time_bomb(self):
        from honeyrun.analyze import Finding, SEVERITIES  # noqa: F401
        import json as _json
        from honeyrun import bait as _bait
        from honeyrun.analyze import analyze as _analyze
        baits = _bait.generate()
        meta = {"phases": [{"name": n, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": []}
                           for n in ("run", "later")]}
        net = [{"kind": "dns", "qname": "c2.example.net", "qtype": 1}]
        line = '1 t connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH'
        trace = {"meta.json": _json.dumps(meta).encode(), "run.strace": line.encode(), "later.strace": line.encode(),
                 "net.jsonl": "\n".join(_json.dumps(r) for r in net).encode()}
        rules = {f.rule for f in _analyze(trace, baits, "offline").findings}
        self.assertIn("network", rules)
        self.assertNotIn("delayed-activation", rules)
