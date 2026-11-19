"""Unit tests for manifest.py. Run: python3 -m unittest -v test_manifest"""

import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import manifest as M


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


class Image:
    """A fake golden image: root fs, a separate /boot and an ESP."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.root = os.path.join(t, "root")
        self.boot = os.path.join(t, "boot")
        self.efi = os.path.join(t, "efi")
        r = self.root
        write(f"{r}/usr/bin/kubelet", b"kubelet-binary", 0o755)
        write(f"{r}/usr/bin/sudo", b"sudo", 0o4755)
        write(f"{r}/etc/nodetrust/build-info", b"golden=1\nkubelet=v1.35.10\n")
        write(f"{r}/etc/nodetrust/ima-policy", b"measure func=BPRM_CHECK\n")
        os.symlink("usr/bin", f"{r}/bin")
        os.makedirs(f"{r}/boot")  # mountpoint, empty in the image
        os.mkfifo(f"{r}/etc/a-fifo")
        write(f"{r}/var/lib/dpkg/info/kubelet.md5sums",
              hashlib.md5(b"kubelet-binary").hexdigest().encode() + b"  usr/bin/kubelet\n")
        write(f"{r}/var/lib/dpkg/info/sudo.md5sums",
              hashlib.md5(b"sudo").hexdigest().encode() + b"  bin/sudo\n")  # via /bin symlink
        write(f"{self.boot}/vmlinuz-7.0.0", b"kernel")
        os.makedirs(f"{self.boot}/efi")
        write(f"{self.efi}/EFI/BOOT/BOOTX64.EFI", b"shim")

    def mounts(self):
        return [("/", self.root, True), ("/boot", self.boot, True), ("/boot/efi", self.efi, False)]

    def close(self):
        self.tmp.cleanup()


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.img = Image()

    def tearDown(self):
        self.img.close()

    def build(self, **kw):
        return M.build(self.img.mounts(), {"ami_id": "ami-test"}, created="2026-11-15T00:00:00Z", **kw)

    def index(self, m):
        return {e["path"]: e for e in m["entries"]}

    def test_paths_from_all_three_filesystems(self):
        idx = self.index(self.build())
        self.assertEqual(idx["/usr/bin/kubelet"]["sha256"], hashlib.sha256(b"kubelet-binary").hexdigest())
        self.assertEqual(idx["/boot/vmlinuz-7.0.0"]["type"], "file")
        self.assertEqual(idx["/boot/efi/EFI/BOOT/BOOTX64.EFI"]["sha256"], hashlib.sha256(b"shim").hexdigest())
        self.assertEqual(idx["/"]["type"], "dir")

    def test_sorted_and_unique(self):
        paths = [e["path"] for e in self.build()["entries"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), len(set(paths)))

    def test_metadata(self):
        idx = self.index(self.build())
        self.assertEqual(idx["/usr/bin/sudo"]["mode"], "4755")
        self.assertEqual(idx["/bin"], {**idx["/bin"], "type": "symlink", "target": "usr/bin"})
        self.assertEqual(idx["/etc/a-fifo"]["kind"], "fifo")
        self.assertNotIn("sha256", idx["/etc/a-fifo"])

    def test_esp_has_no_posix_metadata(self):
        idx = self.index(self.build())
        self.assertNotIn("mode", idx["/boot/efi/EFI/BOOT/BOOTX64.EFI"])
        self.assertIn("mode", idx["/boot/vmlinuz-7.0.0"])

    def test_mountpoint_dir_comes_from_mounted_fs(self):
        # Put a stray file in the root fs's /boot: it is hidden at runtime by
        # the /boot mount, so it is dropped and reported as shadowed.
        write(f"{self.img.root}/boot/stray", b"x")
        m = self.build()
        self.assertNotIn("/boot/stray", self.index(m))
        self.assertEqual(m["shadowed"], ["/boot/stray"])

    def test_deterministic(self):
        a, b = self.build(), self.build()
        self.assertEqual(M.canonical(a), M.canonical(b))
        self.assertEqual(a["entries_sha256"], M.entries_digest(a["entries"]))

    def test_digest_changes_with_content(self):
        a = self.build()["entries_sha256"]
        write(f"{self.img.root}/usr/bin/kubelet", b"tampered", 0o755)
        self.assertNotEqual(a, self.build()["entries_sha256"])

    def test_digest_changes_with_mode(self):
        a = self.build()["entries_sha256"]
        os.chmod(f"{self.img.root}/usr/bin/kubelet", 0o4755)
        self.assertNotEqual(a, self.build()["entries_sha256"])

    def test_build_info_read_from_root(self):
        self.assertEqual(self.build()["build_info"], {"golden": "1", "kubelet": "v1.35.10"})

    def test_requires_root_mount(self):
        with self.assertRaises(M.ManifestError):
            M.build([("/boot", self.img.boot, True)])

    def test_non_utf8_name_is_an_error(self):
        open(os.path.join(os.fsencode(self.img.root), b"bad\xffname"), "wb").close()
        with self.assertRaises(M.ManifestError):
            self.build()


class ResolveTest(unittest.TestCase):
    idx = {
        "/bin": {"type": "symlink", "target": "usr/bin"},
        "/usr/bin": {"type": "dir"},
        "/usr/bin/sh": {"type": "symlink", "target": "dash"},
        "/usr/bin/dash": {"type": "file"},
        "/lib": {"type": "symlink", "target": "/usr/lib"},
        "/loop": {"type": "symlink", "target": "/loop"},
    }

    def test_relative_and_chained(self):
        self.assertEqual(M.resolve(self.idx, "/bin/sh"), "/usr/bin/dash")

    def test_absolute(self):
        self.assertEqual(M.resolve(self.idx, "/lib/x.so"), "/usr/lib/x.so")

    def test_loop(self):
        self.assertIsNone(M.resolve(self.idx, "/loop/x"))

    def test_plain(self):
        self.assertEqual(M.resolve(self.idx, "/usr/bin/dash"), "/usr/bin/dash")


class DpkgTest(unittest.TestCase):
    def setUp(self):
        self.img = Image()
        self.mounts = [(mp, d) for mp, d, _ in self.img.mounts()]

    def tearDown(self):
        self.img.close()

    def test_clean_image(self):
        m = M.build(self.img.mounts())
        r = M.check_dpkg(m, self.mounts)
        self.assertEqual(r["checked"], 2)  # kubelet, and sudo through /bin
        self.assertEqual((r["missing"], r["md5_mismatch"], r["sha_mismatch"]), ([], [], []))

    def test_file_changed_after_manifest(self):
        m = M.build(self.img.mounts())
        write(f"{self.img.root}/usr/bin/kubelet", b"tampered", 0o755)
        r = M.check_dpkg(m, self.mounts)
        self.assertEqual(r["md5_mismatch"], ["kubelet: /usr/bin/kubelet"])
        self.assertEqual(r["sha_mismatch"], ["/usr/bin/kubelet"])

    def test_missing_file(self):
        os.remove(f"{self.img.root}/usr/bin/kubelet")
        r = M.check_dpkg(M.build(self.img.mounts()), self.mounts)
        self.assertEqual(r["missing"], ["kubelet: /usr/bin/kubelet"])

    def test_diversion(self):
        # Another package diverted kubelet's file aside.
        r = self.img.root
        os.rename(f"{r}/usr/bin/kubelet", f"{r}/usr/bin/kubelet.distrib")
        write(f"{r}/var/lib/dpkg/diversions", b"/usr/bin/kubelet\n/usr/bin/kubelet.distrib\nother\n")
        res = M.check_dpkg(M.build(self.img.mounts()), self.mounts)
        self.assertEqual(res["diverted"], 1)
        self.assertEqual((res["missing"], res["md5_mismatch"]), ([], []))

    def test_diversion_owner_keeps_original_path(self):
        # Like vim-runtime: it owns the diversion, so its own help.txt stays
        # at the original path and vim-tiny's copy sits at the .vim-tiny name.
        r = self.img.root
        write(f"{r}/usr/share/doc/help.txt", b"runtime help")
        write(f"{r}/usr/share/doc/help.txt.vim-tiny", b"tiny help")
        write(f"{r}/var/lib/dpkg/info/vim-runtime.md5sums",
              hashlib.md5(b"runtime help").hexdigest().encode() + b"  usr/share/doc/help.txt\n")
        write(f"{r}/var/lib/dpkg/info/vim-tiny:amd64.md5sums",
              hashlib.md5(b"tiny help").hexdigest().encode() + b"  usr/share/doc/help.txt\n")
        write(f"{r}/var/lib/dpkg/diversions",
              b"/usr/share/doc/help.txt\n/usr/share/doc/help.txt.vim-tiny\nvim-runtime\n")
        res = M.check_dpkg(M.build(self.img.mounts()), self.mounts)
        self.assertEqual(res["diverted"], 1)  # only vim-tiny's copy moves
        self.assertEqual((res["missing"], res["md5_mismatch"], res["sha_mismatch"]), ([], [], []))


class CliTest(unittest.TestCase):
    def test_build_digest_find_roundtrip(self):
        img = Image()
        try:
            out = os.path.join(img.tmp.name, "m.json")
            args = ["build", "--mount", f"/={img.root}", "--mount", f"/boot={img.boot}",
                    "--mount", f"/boot/efi={img.efi}:nonposix", "--meta", "ami_id=ami-1", "-o", out]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(M.main(args), 0)
                self.assertEqual(M.main(["digest", out]), 0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(M.main(["find", out, "/boot/vmlinuz-*"]), 0)
            self.assertIn("/boot/vmlinuz-7.0.0", buf.getvalue())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(M.main(["find", out, "/nope*"]), 1)

            # Tamper with the stored file: digest must notice.
            with open(out) as f:
                m = json.load(f)
            m["entries"][-1]["sha256"] = "0" * 64
            with open(out, "w") as f:
                json.dump(m, f)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(M.main(["digest", out]), 1)
        finally:
            img.close()


class StatementTest(unittest.TestCase):
    def setUp(self):
        self.img = Image()
        m = M.build(self.img.mounts(), {"ami_id": "ami-1", "snapshot_id": "snap-1", "region": "r"})
        self.gz = gzip.compress(json.dumps(m).encode())

    def tearDown(self):
        self.img.close()

    def st(self, **kw):
        args = dict(ami="ami-1", snapshot="snap-1", region="r", uri="s3://b/k", key_id="arn:k",
                    signed_at="2026-11-15T00:00:00Z")
        args.update(kw)
        return M.make_statement(self.gz, **args)

    def test_fields_and_canonical_form(self):
        b = self.st()
        d = json.loads(b)
        self.assertEqual(d["schema"], M.STATEMENT_SCHEMA)
        self.assertEqual(d["manifest_gz_sha256"], hashlib.sha256(self.gz).hexdigest())
        self.assertEqual(b, M.canonical(d))  # compact, sorted, no newline
        self.assertEqual(b, self.st())  # deterministic for a fixed time

    def test_refuses_other_ami(self):
        with self.assertRaises(M.ManifestError):
            self.st(ami="ami-2")
        with self.assertRaises(M.ManifestError):
            self.st(snapshot="snap-2")

    def test_refuses_inconsistent_manifest(self):
        m = json.loads(gzip.decompress(self.gz))
        m["entries"][0]["mode"] = "0777"
        self.gz = gzip.compress(json.dumps(m).encode())
        with self.assertRaises(M.ManifestError):
            self.st()


def fake_pe(sections, cert=b"", checksum=0, pe32plus=True):
    """A minimal PE image: DOS header, PE header, optional header with 16
    data directories, a section table, section data, then a certificate table."""
    import struct
    opt_size = (112 if pe32plus else 96) + 16 * 8
    hdr_end = 0x80 + 4 + 20 + opt_size + 40 * len(sections)
    size_of_headers = (hdr_end + 0x1FF) & ~0x1FF
    body, table, ptr = b"", b"", size_of_headers
    for data in sections:
        table += b".s" + b"\0" * 6 + struct.pack("<IIII", len(data), ptr, len(data), ptr) + b"\0" * 16
        body += data
        ptr += len(data)
    cert_off = ptr if cert else 0
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32plus else 0x10B)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<I", opt, 64, checksum)
    nd = 108 if pe32plus else 92
    struct.pack_into("<I", opt, nd, 16)
    struct.pack_into("<II", opt, nd + 4 + 4 * 8, cert_off, len(cert))
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x80) + b"\0" * (0x80 - 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, opt_size, 0)
    head = dos + b"PE\0\0" + coff + bytes(opt) + table
    return head + b"\0" * (size_of_headers - len(head)) + body + cert


class AuthenticodeTest(unittest.TestCase):
    """Real vectors (Ubuntu shim 15.8, GRUB 2.12, kernel 7.0.0-1017-aws) were
    checked against the PCR 4 events of a NitroTPM boot; see the Phase 4
    README. These tests pin down what is excluded from the hash."""

    def ac(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        try:
            return M.authenticode_sha256(f.name)
        finally:
            os.unlink(f.name)

    def test_excludes_checksum_and_certificate(self):
        base = self.ac(fake_pe([b"code" * 100, b"data" * 50], cert=b"SIG1" * 30))
        self.assertIsNotNone(base)
        self.assertEqual(base, self.ac(fake_pe([b"code" * 100, b"data" * 50], cert=b"SIG1" * 30, checksum=0xDEADBEEF)))
        # A different signature of the same length: same image hash.
        self.assertEqual(base, self.ac(fake_pe([b"code" * 100, b"data" * 50], cert=b"SIG2" * 30)))

    def test_covers_sections(self):
        a = self.ac(fake_pe([b"code" * 100], cert=b"S" * 16))
        b = self.ac(fake_pe([b"codE" * 100], cert=b"S" * 16))
        self.assertNotEqual(a, b)

    def test_pe32_and_non_pe(self):
        self.assertIsNotNone(self.ac(fake_pe([b"x" * 64], pe32plus=False)))
        self.assertIsNone(self.ac(b"not an EFI image at all, just text"))
        self.assertIsNone(self.ac(b"MZ" + b"\0" * 10))

    def test_manifest_records_it_under_boot_only(self):
        img = Image()
        try:
            pe = fake_pe([b"k" * 512], cert=b"C" * 32)
            write(f"{img.boot}/vmlinuz-9", pe)
            write(f"{img.root}/usr/lib/x.efi", pe)
            idx = {e["path"]: e for e in M.build(img.mounts())["entries"]}
            self.assertIn("authenticode_sha256", idx["/boot/vmlinuz-9"])
            self.assertNotIn("authenticode_sha256", idx["/usr/lib/x.efi"])
            self.assertNotIn("authenticode_sha256", idx["/boot/efi/EFI/BOOT/BOOTX64.EFI"])  # not a PE here
        finally:
            img.close()


if __name__ == "__main__":
    unittest.main()
