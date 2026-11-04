import base64
import json
import unittest

from honeyrun import bait
from honeyrun.analyze import analyze


def hx(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in s.encode())


def run(strace="", net=(), phase="install"):
    baits = bait.generate()
    host = bait.hostname()
    baits.append(bait.identity(host))
    meta = {"phases": [{"name": phase, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": []}]}
    trace = {"meta.json": json.dumps(meta).encode(), f"{phase}.strace": strace.encode(),
             "net.jsonl": "\n".join(json.dumps(r) for r in net).encode()}
    return host, analyze(trace, baits, "offline")


def dns(name):
    return {"kind": "dns", "qname": name, "qtype": 1}


class Identity(unittest.TestCase):
    def test_hostname_is_unique_and_long_enough_to_match(self):
        a, b = bait.hostname(), bait.hostname()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 16)

    def test_hostname_in_a_dns_label_is_fingerprinting(self):
        baits = bait.generate()
        host = bait.hostname()
        baits.append(bait.identity(host))
        meta = {"phases": [{"name": "install", "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": []}]}
        trace = {"meta.json": json.dumps(meta).encode(), "net.jsonl": json.dumps(dns(f"{host}.abc.oastify.com")).encode()}
        rules = {f.rule for f in analyze(trace, baits, "offline").findings}
        self.assertIn("identity-exfil", rules)
        self.assertIn("exfil-service", rules)
        self.assertNotIn("canary-exfil", rules)       # a hostname is not a credential

    def test_printing_your_own_hostname_is_fine(self):
        baits = bait.generate()
        host = bait.hostname()
        baits.append(bait.identity(host))
        meta = {"phases": [{"name": "install", "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": []}]}
        trace = {"meta.json": json.dumps(meta).encode(), "install.log": f"Linux {host} 6.1 x86_64".encode()}
        rules = {f.rule for f in analyze(trace, baits, "offline").findings}
        self.assertNotIn("identity-exfil", rules)
        self.assertNotIn("secret-in-output", rules)

    def test_identity_bait_is_not_planted_or_counted(self):
        b = bait.identity("dev-abcdefghijklmn")
        self.assertEqual(bait.files([b]), {})
        self.assertEqual(bait.env([b]), {})


class Recon(unittest.TestCase):
    def test_recon_then_unexpected_host_is_high(self):
        s = (f'1 t execve("{hx("/usr/bin/whoami")}", ["{hx("whoami")}"], 0x0 /* 1 vars */) = 0\n'
             f'2 t execve("{hx("/usr/bin/uname")}", ["{hx("uname")}", "{hx("-a")}"], 0x0 /* 1 vars */) = 0\n')
        _, a = run(s, [dns("collect.example.net")])
        hits = [f for f in a.findings if f.rule == "recon-beacon"]
        self.assertEqual([f.severity for f in hits], ["high"])
        self.assertIn("whoami", hits[0].title)

    def test_recon_with_only_registry_traffic_is_quiet(self):
        s = f'1 t execve("{hx("/usr/bin/uname")}", ["{hx("uname")}", "{hx("-m")}"], 0x0 /* 1 vars */) = 0\n'
        _, a = run(s, [dns("registry.npmjs.org")])
        self.assertNotIn("recon-beacon", {f.rule for f in a.findings})

    def test_public_ip_lookup_is_medium(self):
        _, a = run(net=[dns("api.ipify.org")])
        self.assertIn(("medium", "recon"), {(f.severity, f.rule) for f in a.findings})


class ReconAcrossPhases(unittest.TestCase):
    def test_recon_in_run_and_later_is_not_a_time_bomb(self):
        baits = bait.generate()
        s = f'1 t execve("{hx("/usr/bin/whoami")}", ["{hx("whoami")}"], 0x0 /* 1 vars */) = 0\n'
        meta = {"phases": [{"name": n, "cmd": "x", "exit": 0, "seconds": 1, "timed_out": False, "lingering": [],
                            "t0": i * 10, "t1": i * 10 + 9} for i, n in enumerate(("run", "later"))]}
        net = [{"kind": "dns", "qname": "c2.example.net", "qtype": 1, "t": 5},
               {"kind": "dns", "qname": "c2.example.net", "qtype": 1, "t": 15}]
        trace = {"meta.json": json.dumps(meta).encode(), "run.strace": s.encode(), "later.strace": s.encode(),
                 "net.jsonl": "\n".join(json.dumps(r) for r in net).encode()}
        rules = [f.rule for f in analyze(trace, baits, "offline").findings]
        self.assertEqual(rules.count("recon-beacon"), 1)
        self.assertNotIn("delayed-activation", rules)


class MoreExfilHosts(unittest.TestCase):
    def test_oast_and_dnslog_hosts(self):
        for host in ("x1y2.oastify.com", "abc.dnslog.cn", "q.ceye.io", "t.canarytokens.com"):
            _, a = run(net=[dns(host)])
            self.assertIn("exfil-service", {f.rule for f in a.findings}, host)


class CloudInit(unittest.TestCase):
    def test_reading_user_data_is_a_credential_probe(self):
        s = (f'1 t openat(AT_FDCWD, "{hx("/var/lib/cloud/instance/user-data.txt")}", O_RDONLY) = -1 ENOENT '
             f'(No such file or directory)\n')
        _, a = run(s)
        self.assertIn(("high", "credential-probe"), {(f.severity, f.rule) for f in a.findings})


if __name__ == "__main__":
    unittest.main()
