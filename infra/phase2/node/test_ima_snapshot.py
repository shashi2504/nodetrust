"""Tests for ima_snapshot.py. Run from infra/phase2/node with
PYTHONPATH=../../phase1 python3 -m unittest -v test_ima_snapshot"""

import gzip
import hashlib
import os
import struct
import tempfile
import unittest

import ima_replay as R
import ima_snapshot as S


def ng_entry(path, data=None, violation=False):
    if violation:
        fdigest = b"\x00" * 32
    else:
        fdigest = hashlib.sha256(data).digest()
    d = b"sha256:\x00" + fdigest
    n = path + b"\x00"
    tdata = struct.pack("<I", len(d)) + d + struct.pack("<I", len(n)) + n
    tdigest = b"\x00" * 20 if violation else hashlib.sha1(tdata).digest()
    name = b"ima-ng"
    return struct.pack("<I", 10) + tdigest + struct.pack("<I", len(name)) + name + struct.pack("<I", len(tdata)) + tdata


def pcr_after(log, n):
    """Replayed SHA-256 PCR 10 after the first n entries."""
    entries = R.parse_log(log)
    return R.replay_prefixes(entries, "sha256")[n - 1][1]


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = b"".join([
            ng_entry(b"boot_aggregate", b"agg"),
            ng_entry(b"/usr/bin/kubelet", b"kubelet"),
            ng_entry(b"/usr/bin/kubelet", b"kubelet"),     # same pair twice
            ng_entry(b"/usr/bin/kubelet", b"kubelet-v2"),  # same path, new content
            ng_entry(b"/var/log/syslog", violation=True),
            ng_entry(b"/tmp/a\tb\nc\\d\xff", b"odd"),      # hostile file name
            ng_entry(b"/late", b"after the PCR read"),
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def run_snapshot(self, expected):
        logf = os.path.join(self.tmp.name, "log.bin")
        with open(logf, "wb") as f:
            f.write(self.log)
        out = os.path.join(self.tmp.name, "s.tsv.gz")
        rc = S.main(["--out", out, "--log", logf, "--expected", expected.hex(),
                     "--meta", "ami=ami-1", "--retries", "1"])
        with gzip.open(out, "rt", encoding="utf-8") as f:
            return rc, f.read().splitlines()

    def test_prefix_and_pairs(self):
        rc, lines = self.run_snapshot(pcr_after(self.log, 6))  # the 7th entry came after the PCR read
        self.assertEqual(rc, 0)
        meta = dict(l[2:].split("=", 1) for l in lines if l.startswith("# "))
        self.assertEqual(meta["format"], S.FORMAT)
        self.assertEqual(meta["pcr10_match"], "true")
        self.assertEqual(meta["entries_attested"], "6")
        self.assertEqual(meta["entries_after_prefix"], "1")
        self.assertEqual(meta["ami"], "ami-1")
        rows = [l.split("\t") for l in lines if not l.startswith("# ")]
        self.assertEqual(len(rows), 5)  # 6 entries, kubelet pair counted twice
        by_path = {}
        for first, count, h, p in rows:
            by_path.setdefault(p, []).append((int(first), int(count), h))
        self.assertEqual(by_path["/usr/bin/kubelet"],
                         [(1, 2, hashlib.sha256(b"kubelet").hexdigest()),
                          (3, 1, hashlib.sha256(b"kubelet-v2").hexdigest())])
        self.assertEqual(by_path["/var/log/syslog"], [(4, 1, "-")])
        self.assertIn("/tmp/a\\tb\\nc\\\\d\\xff", by_path)
        self.assertNotIn("/late", by_path)  # not attested

    def test_no_match(self):
        rc, lines = self.run_snapshot(b"\x11" * 32)
        self.assertEqual(rc, 1)
        self.assertIn("# pcr10_match=false", lines)
        self.assertEqual([l for l in lines if not l.startswith("# ")], [])

    def test_non_sha256_digest_refused(self):
        d = b"sha1:\x00" + b"\x01" * 20
        n = b"/x\x00"
        tdata = struct.pack("<I", len(d)) + d + struct.pack("<I", len(n)) + n
        entry = (struct.pack("<I", 10) + hashlib.sha1(tdata).digest() + struct.pack("<I", 6) + b"ima-ng"
                 + struct.pack("<I", len(tdata)) + tdata)
        self.log = entry
        logf = os.path.join(self.tmp.name, "log.bin")
        with open(logf, "wb") as f:
            f.write(self.log)
        rc = S.main(["--out", os.path.join(self.tmp.name, "x.gz"), "--log", logf,
                     "--expected", pcr_after(self.log, 1).hex(), "--retries", "1"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
