"""Review fixes for the sandbox agent and the analysis of its traces."""
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from honeyrun import bait
from honeyrun.analyze import analyze, parse_strace
import importlib.util

# agent.py is a standalone script shipped into the container (sandbox/ is not a package), so load it by path
_spec = importlib.util.spec_from_file_location(
    "honeyrun_agent", Path(__file__).resolve().parents[1] / "src" / "honeyrun" / "sandbox" / "agent.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


def hx(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in s.encode())


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Base(unittest.TestCase):
    def setUp(self):
        self.baits = bait.generate()
        self.by_path = {b.path: b for b in self.baits if b.path}
        self.by_env = {b.env: b for b in self.baits if b.env}

    def trace(self, strace="", net=None, phase="install", **ph):
        meta = {"phases": [{"name": phase, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False,
                            "lingering": [], "t0": 1000.0, "t1": 1100.0, **ph}]}
        return {"meta.json": json.dumps(meta).encode(), f"{phase}.strace": strace.encode(),
                "net.jsonl": "\n".join(json.dumps(r) for r in (net or [])).encode()}

    def run_a(self, trace, network="offline"):
        a = analyze(trace, self.baits, network)
        return a, {(f.rule, f.severity) for f in a.findings}

    def rules(self, trace, network="offline"):
        a, _ = self.run_a(trace, network)
        return a, {f.rule for f in a.findings if f.severity != "info"}


class HostSpoofing(Base):
    def req(self, sni, host, tls=True, secret=None, method="POST"):
        secret = secret or self.by_env["GITHUB_TOKEN"].secret
        body = f"{method} /x HTTP/1.1\r\nHost: {host}\r\nAuthorization: {secret}\r\n\r\n".encode()
        rec = {"kind": "tcp", "port": 443 if tls else 80, "host": host, "method": method, "path": "/x",
               "data_b64": b64(body), "bytes": len(body), "t": 1010.0}
        if tls:
            rec.update(sni=sni, tls=True)
        return rec

    def test_tls_host_header_cannot_claim_own_service(self):
        a, rules = self.run_a(self.trace(net=[self.req("evil.example.net", "api.github.com")]))
        self.assertIn(("canary-exfil", "critical"), rules)
        self.assertIn(("host-mismatch", "high"), rules)
        self.assertTrue(any(h["host"] == "evil.example.net" for h in a.hosts))

    def test_plain_http_never_counts_as_own_service(self):
        _, rules = self.run_a(self.trace(net=[self.req(None, "api.github.com", tls=False)]))
        self.assertIn(("canary-exfil", "critical"), rules)

    def test_matching_sni_is_own_service(self):
        _, rules = self.run_a(self.trace(net=[self.req("api.github.com", "api.github.com", method="GET")]))
        self.assertIn(("credential-to-own-service", "info"), rules)
        self.assertFalse({r for r, _ in rules} & {"canary-exfil", "host-mismatch"})


class UploadsToExpectedHosts(Base):
    def rec(self, method, body=b"", host="storage.googleapis.com"):
        data = f"{method} /b HTTP/1.1\r\nHost: {host}\r\n\r\n".encode() + body
        return {"kind": "tcp", "port": 443, "host": host, "sni": host, "tls": True, "method": method,
                "path": "/b", "data_b64": b64(data), "bytes": len(data), "t": 1010.0}

    def test_get_download_stays_expected(self):
        _, rules = self.rules(self.trace(net=[self.rec("GET", host="raw.githubusercontent.com")]))
        self.assertEqual(rules, set())

    def test_post_to_expected_host_is_upload(self):
        _, rules = self.rules(self.trace(net=[self.rec("POST", b"hello")]))
        self.assertEqual(rules, {"upload"})

    def test_large_body_on_get_is_upload(self):
        _, rules = self.rules(self.trace(net=[self.rec("GET", b"x" * 3000, host="huggingface.co")]))
        self.assertEqual(rules, {"upload"})

    def test_canary_still_critical(self):
        r = self.rec("PUT", self.by_env["GITHUB_TOKEN"].secret.encode(), host="storage.googleapis.com")
        _, rules = self.run_a(self.trace(net=[r]))
        self.assertIn(("canary-exfil", "critical"), rules)
        self.assertIn(("upload", "medium"), rules)


class OpenModeIps(Base):
    def connect(self, ip, port=443):
        return f'1 10:00:00.1 connect(3<socket:[1]>, {{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{ip}")}}, 16) = 0\n'

    def test_open_mode_flags_ip_without_lookup(self):
        a, rules = self.run_a(self.trace(self.connect("93.184.216.34")), network="open")
        self.assertIn(("network", "medium"), rules)
        self.assertTrue(any("hard-coded IP" in f.title for f in a.findings))

    def test_open_mode_ip_after_lookup_is_info(self):
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08registry\x05npmjs\x03org\x00\x00\x01\x00\x01"
        lookup = (f'1 10:00:00.0 sendto(4<UDP:[1->2:53]>, "{"".join(f"\\x{c:02x}" for c in q)}", {len(q)}, 0, NULL, 0) = {len(q)}\n')
        _, rules = self.run_a(self.trace(lookup + self.connect("93.184.216.34")), network="open")
        self.assertIn(("network", "info"), rules)
        self.assertNotIn(("network", "medium"), rules)

    def test_open_mode_ignores_private_and_dns_port(self):
        s = self.connect("10.0.0.5") + self.connect("8.8.8.8", 53) + self.connect("127.0.0.11", 53)
        _, rules = self.rules(self.trace(s), network="open")
        self.assertEqual(rules, set())

    def test_offline_still_flags(self):
        _, rules = self.rules(self.trace(self.connect("203.0.113.9")), network="offline")
        self.assertIn("network", rules)


class Lingering(Base):
    def test_run_phase_lingering_is_medium(self):
        _, rules = self.rules(self.trace(phase="run", lingering=[{"pid": 9, "cmdline": "sh -c sleep 8; curl x"}]))
        self.assertIn("lingering-process", rules)

    def test_mcp_phase_excluded(self):
        _, rules = self.rules(self.trace(phase="run", mcp=True, lingering=[{"pid": 9, "cmdline": "server"}]))
        self.assertNotIn("lingering-process", rules)

    def test_run_and_later_do_not_become_time_bomb(self):
        meta = {"phases": [{"name": n, "cmd": "x", "exit": 0, "timed_out": False,
                            "lingering": [{"pid": 9, "cmdline": "node"}]} for n in ("run", "later")]}
        a, rules = self.run_a({"meta.json": json.dumps(meta).encode()})
        self.assertNotIn("delayed-activation", {r for r, _ in rules})

    def test_agent_keeps_watching_for_twenty_seconds(self):
        self.assertGreaterEqual(agent.LINGER_WINDOW, 20)


class Degraded(Base):
    def flagged(self, net):
        t = self.trace(net=net)
        meta = json.loads(t["meta.json"])
        meta["sinkhole_degraded"] = True
        t["meta.json"] = json.dumps(meta).encode()
        return self.run_a(t)[1]

    def test_degraded_with_unexpected_host_is_high(self):
        rules = self.flagged([{"kind": "dns", "qname": "c2.example.net", "qtype": 1, "t": 1010.0}])
        self.assertIn(("incomplete", "high"), rules)

    def test_degraded_alone_is_medium(self):
        rules = self.flagged([{"kind": "dns", "qname": "registry.npmjs.org", "qtype": 1, "t": 1010.0}])
        self.assertIn(("incomplete", "medium"), rules)
        self.assertNotIn(("incomplete", "high"), rules)

    def test_netlog_caps_payload_and_keeps_latest_records(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(agent, "TCP_LOG_CAP", 200_000), \
                mock.patch.object(agent, "RING", 5):
            agent.DEGRADED.clear()
            log = agent.NetLog(os.path.join(d, "net.jsonl"))
            for i in range(30):
                log.write(kind="tcp", port=80, bytes=100000, _raw=b"junk" * 25000)
            log.write(kind="dns", qname="a.example.net", qtype=1)       # own budget: still stored
            log.write(kind="tcp", port=80, bytes=100012, _raw=b"x" * 100000 + b"SECRET-EXFIL")
            log.close()
            recs = [json.loads(x) for x in Path(d, "net.jsonl").read_text().splitlines()]
        self.assertTrue(agent.DEGRADED.is_set())
        agent.DEGRADED.clear()
        self.assertTrue(any(r.get("qname") == "a.example.net" for r in recs))
        last = [r for r in recs if r.get("kind") == "tcp"][-1]
        self.assertTrue(base64.b64decode(last["data_b64"]).endswith(b"SECRET-EXFIL"))   # past the budget, still kept
        big = next(r for r in recs if r.get("kind") == "tcp")
        self.assertLessEqual(len(base64.b64decode(big["data_b64"])), agent.PAYLOAD_CAP)
        self.assertEqual(big["bytes"], 100000)


class Cwd(Base):
    def test_relative_hook_write_in_repo_is_fine(self):
        s = f'1 t openat(AT_FDCWD, "{hx(".git/hooks/pre-commit")}", O_WRONLY|O_CREAT, 0755) = 3\n'
        paths = [e.data["path"] for e in parse_strace(s, "run") if e.kind == "open"]
        self.assertEqual(paths, ["/workspace/repo/.git/hooks/pre-commit"])
        _, rules = self.rules(self.trace(s))
        self.assertNotIn("hook-hijack", rules)

    def test_chdir_then_relative_bait_read(self):
        s = (f'1 t chdir("{hx("/home/runner")}") = 0\n'
             f'1 t openat(AT_FDCWD, "{hx(".ssh/id_ed25519")}", O_RDONLY) = 3\n')
        _, rules = self.rules(self.trace(s))
        self.assertIn("bait-read", rules)

    def test_fchdir_and_fork_inherit(self):
        s = ('1 t fchdir(3</home/runner>) = 0\n'
             '1 t clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 2\n'
             f'2 t open("{hx(".aws/credentials")}", O_RDONLY) = 4\n')
        paths = [e.data["path"] for e in parse_strace(s, "run") if e.kind == "open"]
        self.assertEqual(paths, ["/home/runner/.aws/credentials"])

    def test_decoration_wins(self):
        s = f'1 t openat(AT_FDCWD</tmp>, "{hx("x")}", O_RDONLY) = 3\n'
        self.assertEqual([e.data["path"] for e in parse_strace(s, "run") if e.kind == "open"], ["/tmp/x"])

    def test_agent_traces_chdir_and_io_uring(self):
        for call in ("chdir", "fchdir", "io_uring_setup", "io_uring_enter", "io_uring_register"):
            self.assertIn(call, agent.SYSCALLS.split(","))


class Incomplete(Base):
    def test_missing_meta_with_trace_is_high(self):
        _, rules = self.run_a({"install.strace": b""})
        self.assertIn(("incomplete", "high"), rules)

    def test_garbage_meta_is_high(self):
        _, rules = self.run_a({"meta.json": b"{not json"})
        self.assertIn(("incomplete", "high"), rules)

    def test_empty_phases_is_high(self):
        _, rules = self.run_a({"meta.json": b'{"phases": []}'})
        self.assertIn(("incomplete", "high"), rules)

    def test_nothing_to_run_is_not_an_error(self):
        _, rules = self.run_a({"meta.json": b'{"phases": [], "phases_requested": 0}'})
        self.assertNotIn("incomplete", {r for r, _ in rules})

    def test_static_only_empty_trace_unchanged(self):
        self.assertEqual(analyze({}, self.baits, "offline").findings, [])


class IoUring(Base):
    def test_setup_is_medium(self):
        s = '1 t io_uring_setup(256, {flags=0}) = 5<anon_inode:[io_uring]>\n'
        _, rules = self.run_a(self.trace(s))
        self.assertIn(("io-uring", "medium"), rules)

    def test_node_libuv_is_only_info(self):
        s = (f'1 t execve("{hx("/usr/local/bin/node")}", ["{hx("node")}", "{hx("x.js")}"], 0x0 /* 1 vars */) = 0\n'
             '1 t io_uring_setup(256, {flags=0}) = 5<anon_inode:[io_uring]>\n')
        _, rules = self.run_a(self.trace(s))
        self.assertIn(("io-uring", "info"), rules)
        self.assertNotIn(("io-uring", "medium"), rules)


class ExtractRepo(unittest.TestCase):
    def test_symlink_member_not_followed(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            work = os.path.join(d, "repo")
            os.makedirs(work)
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                link = tarfile.TarInfo("a")
                link.type, link.linkname = tarfile.SYMTYPE, "real"
                real = tarfile.TarInfo("real")
                real.size, real.mode = 4, 0o644
                tf.addfile(real, io.BytesIO(b"orig"))
                tf.addfile(link)
                f = tarfile.TarInfo("a")          # same name again, would write through the link
                f.size, f.mode = 3, 0o644
                tf.addfile(f, io.BytesIO(b"abc"))
            buf.seek(0)
            with mock.patch.object(agent, "WORK", work), mock.patch.object(agent, "chown_tree"):
                agent.extract_repo(buf, 0, 0)
            self.assertEqual(Path(work, "real").read_bytes(), b"orig")   # not written through the link
            self.assertFalse(os.path.islink(os.path.join(work, "a")))
            self.assertEqual(Path(work, "a").read_bytes(), b"abc")


if __name__ == "__main__":
    unittest.main()
