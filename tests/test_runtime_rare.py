import json
import unittest

from honeyrun import bait
from honeyrun.analyze import parse_dns_question, parse_strace_counted
from test_analyze import dns_query, hx
from test_hardening import Base, ex, op

FIX = lambda **k: {"created": [], "modified": [], "deleted": [], "counts": {}, **k}   # noqa: E731


def conn_unix(pid, path, ret="0"):
    return f'{pid} t connect(3, {{sa_family=AF_UNIX, sun_path="{hx(path)}"}}, 110) = {ret}'


def conn_inet(pid, addr, port, ret="-1 ENETUNREACH (Network is unreachable)"):
    return f'{pid} t connect(3, {{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{hx(addr)}")}}, 16) = {ret}'


def dns_send(pid, name, qtype=1):
    pkt = bytearray(dns_query(name))
    pkt[-4:-2] = qtype.to_bytes(2, "big")
    esc = "".join(f"\\x{b:02x}" for b in pkt)
    return f'{pid} t sendto(3<UDP:[127.0.0.1:4000->127.0.0.1:53]>, "{esc}", {len(pkt)}, 0, NULL, 0) = {len(pkt)}'


class Imds(Base):
    def test_connect_attempt_flagged_even_when_it_fails(self):
        a = self.run_(conn_inet(5, "169.254.169.254", 80))
        self.assertEqual([x.severity for x in self.get(a, "imds")], ["high"])

    def test_ipv6_and_any_port(self):
        line = f'5 t connect(3, {{sa_family=AF_INET6, sin6_port=htons(8080), inet_pton(AF_INET6, "{hx("fd00:ec2::254")}", &sin6_addr)}}, 28) = -1 ENETUNREACH (x)'
        self.assertIn("imds", self.rules(self.run_(line)))

    def test_metadata_names_by_dns(self):
        for n in ("metadata.google.internal", "metadata.azure.com", "169.254.169.254.nip.io"):
            self.assertIn("imds", self.rules(self.run_(net=[{"kind": "dns", "qname": n, "qtype": 1}])), n)

    def test_ordinary_host_is_not_imds(self):
        self.assertNotIn("imds", self.rules(self.run_(net=[{"kind": "dns", "qname": "registry.npmjs.org"}])))


class AgentSockets(Base):
    def test_connect_to_decoy_ssh_agent(self):
        a = self.run_(conn_unix(4, "/run/honeyrun/ssh-agent.sock"))
        f = self.get(a, "agent-hijack")
        self.assertEqual([x.severity for x in f], ["high"])
        self.assertIn("SSH agent", f[0].title)

    def test_netlog_record_from_the_agent(self):
        a = self.run_(net=[{"kind": "agent-socket", "sock": "gpg"}])
        self.assertIn("agent-hijack", self.rules(a))

    def test_other_unix_sockets_are_not_flagged(self):
        self.assertNotIn("agent-hijack", self.rules(self.run_(conn_unix(4, "/tmp/other.sock"))))


class InputCapture(Base):
    def test_input_devices_high(self):
        for p in ("/dev/input/event3", "/dev/uinput"):
            self.assertEqual([x.severity for x in self.get(self.run_(op(3, p, "O_RDWR")), "input-capture")], ["high"], p)

    def test_clipboard_and_screen_tools_medium(self):
        for tool in ("xclip", "xdotool", "wl-paste", "pbcopy", "scrot", "import", "grim"):
            a = self.run_(ex(3, f"/usr/bin/{tool}", tool, "-o"))
            self.assertEqual([x.severity for x in self.get(a, "input-capture")], ["medium"], tool)

    def test_failed_exec_is_not_flagged(self):
        self.assertNotIn("input-capture", self.rules(self.run_(ex(3, "/usr/bin/xclip", "xclip", ret="-1 ENOENT (x)"))))


class Shadowing(Base):
    def wr(self, path):
        return op(2, path, "O_WRONLY|O_CREAT|O_TRUNC")

    def test_fake_git_in_local_bin(self):
        for p in ("/home/runner/.local/bin/git", "/home/runner/bin/ssh"):
            a = self.run_(self.wr(p))
            self.assertEqual([x.severity for x in self.get(a, "path-shadow")], ["high"], p)

    def test_uncommon_name_and_reads_are_fine(self):
        self.assertNotIn("path-shadow", self.rules(self.run_(self.wr("/home/runner/.local/bin/mytool"))))
        self.assertNotIn("path-shadow", self.rules(self.run_(op(2, "/home/runner/.local/bin/git"))))

    def test_from_file_snapshot(self):
        a = self.run_(files=FIX(created=[["/home/runner/.local/bin/sudo", 100, "0o755", "23212f62"]]))
        self.assertIn("path-shadow", self.rules(a))

    def test_ld_so_preload_even_when_denied(self):
        a = self.run_(op(2, "/etc/ld.so.preload", "O_WRONLY|O_CREAT", ret="-1 EACCES (x)"))
        self.assertEqual([x.severity for x in self.get(a, "loader-hijack")], ["high"])

    def test_reading_ld_so_preload_is_normal(self):
        self.assertEqual(self.rules(self.run_(op(2, "/etc/ld.so.preload", ret="-1 ENOENT (x)"))), set())

    def test_ld_preload_written_to_rc(self):
        script = "echo 'export LD_PRELOAD=/tmp/x.so' >> ~/.bashrc"
        self.assertIn("loader-hijack", self.rules(self.run_(ex(2, "/bin/sh", "sh", "-c", script))))

    def test_shared_library_in_home(self):
        a = self.run_(files=FIX(created=[["/home/runner/.hidden/libx.so", 50, "0o644", "00000000"]]))
        self.assertEqual([x.severity for x in self.get(a, "loader-hijack")], ["medium"])
        a = self.run_(files=FIX(created=[["/home/runner/.hidden/libx.so", 50, "0o644", "7f454c46"]]))
        self.assertEqual([x.severity for x in self.get(a, "loader-hijack")], ["high"])
        a = self.run_(files=FIX(created=[["/home/runner/.local/lib/python3.11/site-packages/n/x.so", 50, "0o644", "7f454c46"]]))
        self.assertEqual(self.get(a, "loader-hijack"), [])

    def test_git_hooks_outside_the_repo(self):
        a = self.run_(self.wr("/home/runner/other/.git/hooks/pre-commit"))
        self.assertEqual([x.severity for x in self.get(a, "hook-hijack")], ["high"])
        a = self.run_(self.wr("/home/runner/.config/git/hooks/post-checkout"))
        self.assertIn("hook-hijack", self.rules(a))

    def test_own_repo_hooks_are_not_hijack(self):
        a = self.run_(self.wr("/workspace/repo/.git/hooks/pre-commit"))
        self.assertNotIn("hook-hijack", self.rules(a))


class AppCredentialStores(Base):
    PATHS = (
        "/home/runner/.config/discord/Local Storage/leveldb/000003.log",
        "/home/runner/.config/Slack/storage/root-state.json",
        "/home/runner/.local/share/TelegramDesktop/tdata/key_datas",
        "/home/runner/.config/Signal/config.json",
        "/home/runner/.steam/steam/ssfn1234567",
        "/home/runner/.config/filezilla/recentservers.xml",
        "/home/runner/.config/gcloud/credentials.db",
        "/home/runner/.config/gcloud/access_tokens.db",
        "/home/runner/.azure/accessTokens.json",
        "/home/runner/.config/doctl/config.yaml",
        "/home/runner/.terraform.d/credentials.tfrc.json",
        "/home/runner/.config/hub",
        "/home/runner/Documents/passwords.kdbx",
    )

    def test_each_store_is_a_high_probe_even_when_missing(self):
        for p in self.PATHS:
            a = self.run_(op(3, p, ret="-1 ENOENT (x)"))
            self.assertEqual([x.severity for x in self.get(a, "credential-probe")], ["high"], p)

    def test_vault_token_is_bait_and_probe(self):
        self.assertIn("bait-read", self.rules(self.run_(op(3, "/home/runner/.vault-token"))))

    def test_repo_fixture_leveldb_is_exempt(self):
        self.assertEqual(self.rules(self.run_(op(3, "/workspace/repo/test/Local Storage/leveldb/x"))), set())

    def test_new_bait_present_and_well_formed(self):
        by = {b.path: b for b in bait.generate() if b.path}
        for p in (".config/gcloud/application_default_credentials.json", ".vault-token"):
            b = by[p]
            self.assertTrue(b.secret in b.content)
            self.assertTrue(all(len(n) >= 16 for n in bait.bait_needles(b)))
        a, b2 = bait.generate(), bait.generate()
        self.assertNotEqual({x.secret for x in a}, {x.secret for x in b2})


class UnusualChannels(Base):
    def test_raw_socket_attempts(self):
        for line in ("9 t socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = -1 EPERM (Operation not permitted)",
                     "9 t socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) = -1 EPERM (x)",
                     "9 t socket(AF_INET6, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_ICMPV6) = 3"):
            self.assertEqual([x.severity for x in self.get(self.run_(line), "raw-socket")], ["high"], line)

    def test_netlink_and_tcp_sockets_are_normal(self):
        for line in ("9 t socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3",
                     "9 t socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3"):
            self.assertEqual(self.rules(self.run_(line)), set(), line)

    def test_dns_question_parser(self):
        pkt = bytearray(dns_query("a.evil.example.net"))
        pkt[-4:-2] = (16).to_bytes(2, "big")
        self.assertEqual(parse_dns_question(bytes(pkt)), ("a.evil.example.net", 16))

    def test_txt_lookup_from_strace_and_sinkhole(self):
        a = self.run_(dns_send(4, "c2.evil.example.net", 16))
        self.assertEqual([x.severity for x in self.get(a, "dns-txt")], ["medium"])
        a = self.run_(net=[{"kind": "dns", "qname": "c2.evil.example.net", "qtype": 16}])
        self.assertIn("dns-txt", self.rules(a))

    def test_a_lookup_and_registry_txt_are_not_txt_findings(self):
        self.assertNotIn("dns-txt", self.rules(self.run_(dns_send(4, "c2.evil.example.net", 1))))
        self.assertNotIn("dns-txt", self.rules(self.run_(dns_send(4, "pypi.org", 16))))

    def test_exfil_services_by_hostname(self):
        for n in ("pastebin.com", "transfer.sh", "0x0.st", "discord.com", "api.telegram.org", "hooks.slack.com",
                  "webhook.site", "abcd.ngrok-free.app", "abcdefgh.onion", "x.oast.pro", "interact.sh",
                  "y.burpcollaborator.net", "file.io", "paste.ee"):
            a = self.run_(net=[{"kind": "dns", "qname": n, "qtype": 1}])
            self.assertEqual([x.severity for x in self.get(a, "exfil-service")], ["high"], n)

    def test_lookalike_hosts_are_fine(self):
        for n in ("notpastebin.com.example.net", "github.com", "registry.npmjs.org"):
            self.assertNotIn("exfil-service", self.rules(self.run_(net=[{"kind": "dns", "qname": n}])), n)


class ProcessTricks(Base):
    def test_interpreter_renamed_to_system_name(self):
        for name0 in ("systemd", "[kworker/0:1]", "sshd"):
            a = self.run_(ex(3, "/usr/bin/python3", name0, "-c", "pass"))
            self.assertEqual([x.severity for x in self.get(a, "disguised-process")], ["high"], name0)

    def test_normal_argv0_is_fine(self):
        self.assertEqual(self.rules(self.run_(ex(3, "/usr/bin/python3", "python3", "x.py"))), set())
        self.assertEqual(self.rules(self.run_(ex(3, "/usr/lib/systemd/systemd", "systemd"))), set())

    def clones(self, n, flags="SIGCHLD"):
        return "\n".join(f"1 t clone(child_stack=NULL, flags={flags}) = {100 + i}" for i in range(n))

    def test_fork_bomb(self):
        a = self.run_(self.clones(301))
        self.assertEqual([x.severity for x in self.get(a, "fork-bomb")], ["high"])
        self.assertEqual(self.get(self.run_(self.clones(300)), "fork-bomb"), [])

    def test_threads_do_not_count(self):
        a = self.run_(self.clones(500, "CLONE_VM|CLONE_FS|CLONE_THREAD|CLONE_SIGHAND"))
        self.assertEqual(self.get(a, "fork-bomb"), [])
        self.assertEqual(parse_strace_counted(self.clones(3), "x")[1], 3)


class AntiForensics(Base):
    def test_deleted_executed_script(self):
        a = self.run_(ex(3, "/usr/local/bin/node", "node", "scripts/setup.js"),
                      files=FIX(deleted=[["/workspace/repo/scripts/setup.js", 100, "0o644", "2f2f2046"]]))
        self.assertEqual([x.severity for x in self.get(a, "anti-forensics")], ["medium"])

    def test_deleted_unrelated_file_is_fine(self):
        a = self.run_(files=FIX(deleted=[["/workspace/repo/docs/notes.txt", 10, "0o644", "00000000"]]))
        self.assertEqual(self.get(a, "anti-forensics"), [])

    def test_history_deleted_or_truncated(self):
        a = self.run_(files=FIX(deleted=[["/home/runner/.bash_history", 10, "0o600", "00000000"]]))
        self.assertIn("anti-forensics", self.rules(a))
        a = self.run_(op(3, "/home/runner/.bash_history", "O_WRONLY|O_TRUNC"))
        self.assertIn("anti-forensics", self.rules(a))
        a = self.run_(ex(3, "/bin/sh", "sh", "-c", "rm -f ~/.bash_history; history -c"))
        self.assertIn("anti-forensics", self.rules(a))

    def test_reading_history_is_a_probe_not_anti_forensics(self):
        a = self.run_(op(3, "/home/runner/.bash_history"))
        self.assertNotIn("anti-forensics", self.rules(a))
        self.assertIn("credential-probe", self.rules(a))


if __name__ == "__main__":
    unittest.main()
