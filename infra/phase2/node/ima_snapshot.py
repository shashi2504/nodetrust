#!/usr/bin/env python3
"""Snapshot a node's attested IMA measurements (Phase 2, step 2.4).

Reads SHA-256 PCR 10 first, then the binary IMA log, and keeps the shortest
log prefix that replays to that PCR (ima_replay.py from Phase 1). Only that
prefix is attested by the TPM, so only it is written out. Each distinct
(SHA-256, path) pair of the ima-ng entries becomes one line:

    # key=value                        metadata
    first<TAB>count<TAB>sha256<TAB>path

A violation (IMA could not measure the file) has "-" as its hash. Paths are
escaped: backslash, tab and newline as \\\\, \\t, \\n, and bytes that are not
valid UTF-8 as \\xHH, so a crafted file name cannot forge fields or lines.
The Go verifier (pkg/imapolicy) reads this format.

Exit status: 0 if the log replays to the PCR, 1 if not, 2 on errors.
"""
import argparse
import datetime
import gzip
import struct
import sys

import ima_replay as R

FORMAT = "nodetrust-ima-snapshot/1"


def decode_ima_ng(tdata):
    """ima-ng template data -> (algo, digest bytes, path bytes)."""
    off = 0
    fields = []
    while off < len(tdata):
        if off + 4 > len(tdata):
            raise R.ParseError("truncated ima-ng field length")
        (n,) = struct.unpack_from("<I", tdata, off)
        off += 4
        if off + n > len(tdata):
            raise R.ParseError("truncated ima-ng field")
        fields.append(tdata[off:off + n])
        off += n
    if len(fields) != 2:
        raise R.ParseError(f"ima-ng entry has {len(fields)} fields, want 2")
    d, name = fields
    sep = d.find(b"\x00")
    if sep < 0 or not d[:sep].endswith(b":"):
        raise R.ParseError("ima-ng digest field has no 'algo:' prefix")
    algo = d[:sep - 1].decode("ascii")
    digest = d[sep + 1:]
    if name.endswith(b"\x00"):
        name = name[:-1]
    return algo, digest, name


def escape_path(raw):
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:  # a byte that was not valid UTF-8
            out.append("\\x%02x" % (o - 0xDC00))
        else:
            out.append(ch)
    return "".join(out)


def snapshot(log_bytes, quoted, bank="sha256"):
    entries = R.parse_log(log_bytes)
    matched, used, bad, after = R.match_prefix(entries, bank, quoted)
    meta = {
        "bank": bank,
        "pcr10": quoted.hex(),
        "pcr10_match": "true" if matched else "false",
        "entries_total": str(len(entries)),
        "entries_attested": str(used if matched else 0),
        "entries_after_prefix": str(after if matched else len(entries)),
        "sha1_template_mismatches": str(bad),
    }
    pairs = {}
    if matched:
        zero20 = b"\x00" * 20
        for i, (pcr, digest, name, tdata) in enumerate(entries[:len(entries) - after]):
            if pcr != R.IMA_PCR:
                continue
            if name != "ima-ng":
                raise R.ParseError(f"entry {i} uses template {name!r}, want ima-ng")
            algo, fdigest, path = decode_ima_ng(tdata)
            if digest == zero20:
                h = "-"
            elif algo != "sha256" or len(fdigest) != 32:
                raise R.ParseError(f"entry {i} has a {algo} file digest; boot with ima_hash=sha256")
            else:
                h = fdigest.hex()
            key = (h, path)
            if key in pairs:
                pairs[key][1] += 1
            else:
                pairs[key] = [i, 1]
    return meta, pairs


def write(out, meta, pairs):
    with gzip.open(out, "wt", encoding="utf-8", newline="\n") as f:
        for k, v in meta.items():
            f.write(f"# {k}={v}\n")
        for (h, path), (first, count) in sorted(pairs.items(), key=lambda kv: kv[1][0]):
            f.write(f"{first}\t{count}\t{h}\t{escape_path(path)}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", default=R.LOG_PATH)
    ap.add_argument("--expected", help="PCR 10 as hex instead of reading the TPM (tests)")
    ap.add_argument("--meta", action="append", default=[], help="extra KEY=VALUE metadata")
    ap.add_argument("--retries", type=int, default=3)
    a = ap.parse_args(argv)

    meta = pairs = None
    for _ in range(max(1, a.retries)):
        # PCR first, then the log (see ima_replay.py).
        quoted = bytes.fromhex(a.expected) if a.expected else R.read_pcr("sha256")
        with open(a.log, "rb") as f:
            raw = f.read()
        try:
            meta, pairs = snapshot(raw, quoted)
        except R.ParseError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if meta["pcr10_match"] == "true":
            break
    head = {"format": FORMAT,
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    for kv in a.meta:
        k, _, v = kv.partition("=")
        head[k] = v
    head.update(meta)
    write(a.out, head, pairs)
    print(f"snapshot {a.out}: match={meta['pcr10_match']} attested={meta['entries_attested']} "
          f"after_prefix={meta['entries_after_prefix']} distinct={len(pairs)}")
    return 0 if meta["pcr10_match"] == "true" else 1


if __name__ == "__main__":
    sys.exit(main())
