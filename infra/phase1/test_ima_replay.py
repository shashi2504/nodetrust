"""Unit tests for ima_replay.py using synthetic IMA logs.

Run: python3 infra/phase1/test_ima_replay.py -v

These tests check the parser and replay against a software model of the
kernel's extend rule. The real check is the replay on NitroTPM in probe.sh.
"""
import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ima_replay  # noqa: E402


def ima_ng_data(path, content):
    """Template data for ima-ng: length-prefixed d-ng and n-ng fields."""
    d_ng = b"sha256:\x00" + hashlib.sha256(content).digest()
    n_ng = path.encode() + b"\x00"
    return struct.pack("<I", len(d_ng)) + d_ng + struct.pack("<I", len(n_ng)) + n_ng


class FakeKernel:
    """Builds a binary log and extends PCR 10 in every bank, as IMA does."""

    def __init__(self):
        self.log = bytearray()
        self.pcr = {b: b"\x00" * s for b, s in ima_replay.BANKS.items()}

    def measure(self, path, content, template="ima-ng", violation=False, pcr=10):
        tdata = ima_ng_data(path, content)
        digest = b"\x00" * 20 if violation else hashlib.sha1(tdata).digest()
        name = template.encode()
        self.log += struct.pack("<I", pcr) + digest
        self.log += struct.pack("<I", len(name)) + name
        self.log += struct.pack("<I", len(tdata)) + tdata
        if pcr == 10:
            for bank, size in ima_replay.BANKS.items():
                m = b"\xff" * size if violation else hashlib.new(bank, tdata).digest()
                self.pcr[bank] = hashlib.new(bank, self.pcr[bank] + m).digest()


def sample():
    k = FakeKernel()
    k.measure("boot_aggregate", b"aggregate")
    k.measure("/usr/bin/kubelet", b"kubelet binary")
    k.measure("/etc/kubernetes/kubelet.conf", b"conf", violation=True)
    k.measure("/usr/bin/containerd", b"containerd binary")
    k.measure("/other/pcr", b"x", pcr=11)  # other PCRs are ignored
    return k


class ReplayTest(unittest.TestCase):
    def test_every_bank_matches(self):
        k = sample()
        entries = ima_replay.parse_log(bytes(k.log))
        self.assertEqual(len(entries), 5)
        for bank in ima_replay.BANKS:
            value, used, bad = ima_replay.replay(entries, bank)
            self.assertEqual(used, 4)
            self.assertEqual(bad, 0)
            self.assertEqual(value, k.pcr[bank], bank)

    def test_edited_entry_is_caught(self):
        k = sample()
        log = bytes(k.log).replace(b"/usr/bin/kubelet", b"/usr/bin/kubelex")
        value, _, bad = ima_replay.replay(ima_replay.parse_log(log), "sha256")
        self.assertEqual(bad, 1)
        self.assertNotEqual(value, k.pcr["sha256"])

    def test_dropped_entry_is_caught(self):
        full = sample()
        partial = FakeKernel()
        partial.measure("boot_aggregate", b"aggregate")
        partial.measure("/usr/bin/kubelet", b"kubelet binary")
        value, _, _ = ima_replay.replay(ima_replay.parse_log(bytes(partial.log)), "sha256")
        self.assertNotEqual(value, full.pcr["sha256"])

    def test_legacy_template_rejected(self):
        k = FakeKernel()
        k.measure("/usr/bin/x", b"x", template="ima")
        with self.assertRaises(ima_replay.ParseError):
            ima_replay.parse_log(bytes(k.log))

    def test_truncated_log_rejected(self):
        k = sample()
        with self.assertRaises(ima_replay.ParseError):
            ima_replay.parse_log(bytes(k.log)[:-3])

    def test_entries_after_pcr_read_still_match(self):
        # The PCR is read, then the kernel measures two more files before the
        # log is read. The prefix up to the PCR read must match.
        k = sample()
        quoted = k.pcr["sha256"]
        k.measure("/tmp/new-file-1", b"one")
        k.measure("/tmp/new-file-2", b"two")
        matched, used, bad, after = ima_replay.match_prefix(
            ima_replay.parse_log(bytes(k.log)), "sha256", quoted)
        self.assertTrue(matched)
        # 3 entries follow the match: sample()'s PCR 11 entry plus the 2 new ones.
        self.assertEqual((used, bad, after), (4, 0, 3))

    def test_zero_pcr_with_entries_fails(self):
        # IMA extends PCR 10 with boot_aggregate before any user program runs,
        # so an all-zero PCR next to a non-empty log must not match.
        k = sample()
        matched, _, _, _ = ima_replay.match_prefix(
            ima_replay.parse_log(bytes(k.log)), "sha256", b"\x00" * 32)
        self.assertFalse(matched)

    def test_edit_inside_matching_prefix_fails(self):
        k = sample()
        quoted = k.pcr["sha256"]
        log = bytes(k.log).replace(b"/usr/bin/kubelet", b"/usr/bin/kubelex")
        matched, _, _, _ = ima_replay.match_prefix(ima_replay.parse_log(log), "sha256", quoted)
        self.assertFalse(matched)

    def test_read_pcr_parses_tpm2_tools_output(self):
        value = bytes(range(32))
        sample_out = f"  sha256:\n    10: 0x{value.hex().upper()}\n"

        class Done:
            stdout = sample_out

        orig = ima_replay.subprocess.run
        ima_replay.subprocess.run = lambda *a, **kw: Done()
        try:
            self.assertEqual(ima_replay.read_pcr("sha256"), value)
        finally:
            ima_replay.subprocess.run = orig

    def test_main_exit_codes(self):
        k = sample()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes(k.log))
            path = f.name
        try:
            good = k.pcr["sha256"].hex()
            bad = "00" * 32
            with open(os.devnull, "w") as null:
                old = sys.stdout
                sys.stdout = null
                try:
                    rc_good = ima_replay.main(["--log", path, "--expected", good])
                    rc_bad = ima_replay.main(["--log", path, "--expected", bad])
                finally:
                    sys.stdout = old
            self.assertEqual(rc_good, 0)
            self.assertEqual(rc_bad, 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
