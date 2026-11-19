#!/usr/bin/env python3
"""Replay the IMA binary measurement log and compare it with TPM PCR 10.

The kernel's binary log stores, for every measurement, the PCR index, the
SHA-1 template digest and the raw template data. For every allocated PCR bank
the kernel extends PCR 10 with HASH_bank(template_data), and a violation
(logged with an all-zero digest) is extended as all 0xFF bytes. This script
redoes that in software so the result can be compared with the live PCR.

Used by probe.sh in Phase 1. The verifier (Phase 4) implements the same rule
in Go; this script stays as an independent cross-check.

Exit status: 0 if the replay matches the PCR, 1 if not, 2 on a usage or
parse error.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys

LOG_PATH = "/sys/kernel/security/ima/binary_runtime_measurements"
IMA_PCR = 10
BANKS = {"sha1": 20, "sha256": 32, "sha384": 48}


class ParseError(Exception):
    pass


def parse_log(data):
    """Parse a binary IMA log (host byte order, x86 little endian).

    Returns a list of (pcr, sha1_template_digest, template_name, template_data).
    """
    entries = []
    off = 0
    n = len(data)
    while off < n:
        try:
            (pcr,) = struct.unpack_from("<I", data, off)
            off += 4
            digest = data[off:off + 20]
            off += 20
            (name_len,) = struct.unpack_from("<I", data, off)
            off += 4
            name = data[off:off + name_len].decode("ascii")
            off += name_len
            (data_len,) = struct.unpack_from("<I", data, off)
            off += 4
            tdata = data[off:off + data_len]
            off += data_len
        except (struct.error, UnicodeDecodeError) as exc:
            raise ParseError(f"entry {len(entries)} at offset {off}: {exc}") from exc
        if len(digest) != 20 or len(tdata) != data_len:
            raise ParseError(f"entry {len(entries)} truncated at offset {off}")
        if name == "ima":
            # The legacy "ima" template hashes its fields differently. The
            # nodetrust kernel command line selects ima-ng, so refuse it.
            raise ParseError(f"entry {len(entries)} uses the legacy 'ima' template; boot with ima_template=ima-ng")
        entries.append((pcr, digest, name, tdata))
    return entries


def replay(entries, bank, pcr_index=IMA_PCR):
    """Return (pcr_value, entries_used, sha1_mismatches) for one bank."""
    values = replay_prefixes(entries, bank, pcr_index)
    if not values:
        return b"\x00" * BANKS[bank], 0, 0
    _idx, value, used, bad = values[-1]
    return value, used, bad


def replay_prefixes(entries, bank, pcr_index=IMA_PCR):
    """Replay PCR 10 entry by entry.

    Returns one tuple per PCR-10 entry: (entry_index, pcr_value_after_it,
    pcr10_entries_so_far, sha1_mismatches_so_far). The verifier accepts a log
    when some prefix replays to the quoted PCR, because the kernel can append
    entries after the PCR was read.
    """
    size = BANKS[bank]
    value = b"\x00" * size
    used = 0
    sha1_mismatches = 0
    zero20 = b"\x00" * 20
    out = []
    for i, (pcr, digest, _name, tdata) in enumerate(entries):
        if pcr != pcr_index:
            continue
        used += 1
        if digest == zero20:
            measurement = b"\xff" * size  # violation
        else:
            if hashlib.sha1(tdata).digest() != digest:
                sha1_mismatches += 1
            measurement = hashlib.new(bank, tdata).digest()
        value = hashlib.new(bank, value + measurement).digest()
        out.append((i, value, used, sha1_mismatches))
    return out


def match_prefix(entries, bank, quoted, pcr_index=IMA_PCR):
    """Find the shortest log prefix whose replay equals the quoted PCR.

    Returns (matched, pcr10_entries_in_prefix, sha1_mismatches_in_prefix,
    entries_after_prefix).
    """
    for idx, value, used, bad in replay_prefixes(entries, bank, pcr_index):
        if value == quoted:
            return bad == 0, used, bad, len(entries) - idx - 1
    return False, 0, 0, 0


def read_pcr(bank, pcr_index=IMA_PCR):
    """Read one PCR with tpm2-tools from stdout.

    No temporary file: under a policy that measures every file root reads, a
    fresh temp file per read would itself add an IMA entry each time.
    """
    out = subprocess.run(
        ["tpm2_pcrread", f"{bank}:{pcr_index}"],
        check=True, capture_output=True, text=True,
    ).stdout
    m = re.search(rf"^\s*{pcr_index}\s*:\s*0x([0-9A-Fa-f]+)\s*$", out, re.MULTILINE)
    if not m:
        raise RuntimeError(f"could not parse tpm2_pcrread output: {out!r}")
    raw = bytes.fromhex(m.group(1))
    if len(raw) != BANKS[bank]:
        raise RuntimeError(f"tpm2_pcrread returned {len(raw)} bytes for {bank}:{pcr_index}")
    return raw


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default=LOG_PATH, help="binary IMA log path")
    ap.add_argument("--bank", default="sha256", choices=sorted(BANKS))
    ap.add_argument("--expected", help="expected PCR 10 as hex, instead of reading the TPM")
    ap.add_argument("--retries", type=int, default=3,
                    help="extra attempts if no prefix matches")
    args = ap.parse_args(argv)

    result = None
    for _attempt in range(max(1, args.retries)):
        # PCR first, then the log: the kernel adds an entry to the log before
        # it extends the PCR, so a log read after the PCR read always holds
        # every entry the PCR covers, plus possibly a few newer ones.
        quoted = bytes.fromhex(args.expected) if args.expected else read_pcr(args.bank)
        with open(args.log, "rb") as f:
            raw = f.read()
        try:
            entries = parse_log(raw)
        except ParseError as exc:
            print(json.dumps({"error": str(exc)}))
            return 2
        matched, used, bad, after = match_prefix(entries, args.bank, quoted)
        full_value, _, full_bad = replay(entries, args.bank)
        result = {
            "bank": args.bank,
            "entries_total": len(entries),
            "entries_pcr10_in_matching_prefix": used,
            "entries_after_prefix": after,
            "templates": sorted({e[2] for e in entries}),
            "sha1_digest_mismatches": bad if matched else full_bad,
            "pcr": quoted.hex(),
            "replayed_full_log": full_value.hex(),
            "match": matched,
        }
        if matched:
            break
    print(json.dumps(result, indent=2))
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
