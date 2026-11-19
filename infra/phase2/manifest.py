#!/usr/bin/env python3
"""Reference manifest for a golden AMI (blueprint Phase 2, step 2.1).

The manifest lists every file of the image's root filesystem, /boot and the
EFI system partition, read offline from a volume made from the AMI's
snapshot. Each regular file gets its SHA-256; directories, symlinks and
special files are listed with their metadata so the verifier can tell an
added or replaced file from an expected one.

Subcommands
  build      walk mounted filesystems and write manifest JSON
  digest     recompute entries_sha256 of a manifest and print a summary
  find       print "sha256  path" for entries matching a glob
  check-dpkg cross-check the image's dpkg md5sums against the files and
             the manifest (independent check that the read was correct)
  statement  write the statement that gets signed (step 2.2)

Canonical form: entries are sorted by path, and entries_sha256 is the SHA-256
of json.dumps(entries, sort_keys=True, separators=(",", ":"),
ensure_ascii=False) encoded as UTF-8. Two builds of the same snapshot give the
same entries_sha256; only "created" differs.

Standard library only, so it runs on a stock Ubuntu builder.
"""

import argparse
import datetime
import fnmatch
import gzip
import hashlib
import json
import os
import stat
import sys

SCHEMA = "nodetrust.dev/manifest/v1"
STATEMENT_SCHEMA = "nodetrust.dev/manifest-statement/v1"
GENERATOR = "manifest.py/2"
CHUNK = 1 << 20


class ManifestError(Exception):
    pass


# --- helpers ------------------------------------------------------------------


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entries_digest(entries):
    return hashlib.sha256(canonical(entries)).hexdigest()


def hash_file(path, algos=("sha256",)):
    hs = [hashlib.new(a) for a in algos]
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            for h in hs:
                h.update(b)
    return [h.hexdigest() for h in hs]


def open_manifest(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def join(mountpoint, rel):
    """Image path for a path relative to a mount's root ("" is the root)."""
    if not rel:
        return mountpoint
    if mountpoint == "/":
        return "/" + rel
    return mountpoint + "/" + rel


def under(path, mountpoint):
    """True if path is strictly inside mountpoint."""
    if mountpoint == "/":
        return path != "/"
    return path.startswith(mountpoint + "/")


def parse_mount(spec):
    """'/boot/efi=/mnt/nt/efi:nonposix' -> ('/boot/efi', '/mnt/nt/efi', False)."""
    if "=" not in spec:
        raise ManifestError(f"bad --mount {spec!r}; want MOUNTPOINT=DIR[:nonposix]")
    mp, d = spec.split("=", 1)
    posix = True
    if d.endswith(":nonposix"):
        d, posix = d[: -len(":nonposix")], False
    if not mp.startswith("/") or (mp != "/" and mp.endswith("/")):
        raise ManifestError(f"mountpoint {mp!r} must be absolute with no trailing slash")
    if not os.path.isdir(d):
        raise ManifestError(f"{d} is not a directory")
    return mp, d, posix


def parse_kv_file(path):
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


# --- Authenticode (step 4.1) ----------------------------------------------------


def authenticode_sha256(path):
    """PE/COFF Authenticode SHA-256 of an EFI image, or None if it is not one.

    This is the digest UEFI firmware and shim extend into PCR 4 for every
    EFI application they start (shim, GRUB, the kernel's EFI stub). The image
    is hashed without its checksum field, without the certificate table
    directory entry and without the certificate table itself (Microsoft PE
    Authenticode spec, "Calculating the PE Image Hash").
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    u16 = lambda o: int.from_bytes(data[o:o + 2], "little")
    u32 = lambda o: int.from_bytes(data[o:o + 4], "little")
    pe = u32(0x3C)
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    coff = pe + 4
    nsect, opt_size = u16(coff + 2), u16(coff + 16)
    opt = coff + 20
    magic = u16(opt)
    if magic == 0x20B:      # PE32+
        ndd_off = opt + 108
    elif magic == 0x10B:    # PE32
        ndd_off = opt + 92
    else:
        return None
    checksum = opt + 64
    size_of_headers = u32(opt + 60)
    ndd = u32(ndd_off)
    cert_entry = ndd_off + 4 + 4 * 8          # data directory 4: the certificate table
    cert_off, cert_size = (u32(cert_entry), u32(cert_entry + 4)) if ndd > 4 else (0, 0)
    if size_of_headers > len(data) or cert_entry + 8 > size_of_headers:
        return None
    h = hashlib.sha256()
    h.update(data[:checksum])
    if ndd > 4:
        h.update(data[checksum + 4:cert_entry])
        h.update(data[cert_entry + 8:size_of_headers])
    else:
        h.update(data[checksum + 4:size_of_headers])
    sections = []
    table = opt + opt_size
    for i in range(nsect):
        s = table + 40 * i
        size, ptr = u32(s + 16), u32(s + 20)
        if size:
            sections.append((ptr, size))
    hashed = size_of_headers
    for ptr, size in sorted(sections):
        h.update(data[ptr:ptr + size])
        hashed += size
    end = cert_off if cert_off else len(data)
    if end > hashed:
        h.update(data[hashed:end])
    return h.hexdigest()


# --- build --------------------------------------------------------------------


def _name(raw, where):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ManifestError(f"file name is not UTF-8 under {where}: {raw!r}") from None


def walk_mount(mountpoint, top, posix=True):
    """Yield (image_path, entry) for everything on the filesystem at top.

    Does not follow symlinks or cross into other filesystems mounted below top.
    """
    top_b = os.fsencode(top)
    root_dev = os.lstat(top_b).st_dev

    def entry_for(full_b, rel, st):
        e = {"path": join(mountpoint, rel)}
        m = st.st_mode
        if stat.S_ISREG(m):
            e["type"] = "file"
            e["size"] = st.st_size
            e["sha256"] = hash_file(full_b)[0]
            if mountpoint.startswith("/boot"):
                # EFI images (shim, GRUB, the kernel's EFI stub): the digest
                # firmware and shim put in PCR 4.
                ac = authenticode_sha256(full_b)
                if ac:
                    e["authenticode_sha256"] = ac
            try:
                cap = os.getxattr(full_b, b"security.capability", follow_symlinks=False)
                e["capability"] = cap.hex()
            except OSError:
                pass
        elif stat.S_ISDIR(m):
            e["type"] = "dir"
        elif stat.S_ISLNK(m):
            e["type"] = "symlink"
            e["target"] = _name(os.readlink(full_b), e["path"])
        else:
            e["type"] = "other"
            e["kind"] = (
                "fifo" if stat.S_ISFIFO(m) else
                "socket" if stat.S_ISSOCK(m) else
                "char" if stat.S_ISCHR(m) else
                "block" if stat.S_ISBLK(m) else "unknown"
            )
        if posix:
            e["mode"] = format(stat.S_IMODE(m), "04o")
            e["uid"] = st.st_uid
            e["gid"] = st.st_gid
        return e

    st = os.lstat(top_b)
    yield join(mountpoint, ""), entry_for(top_b, "", st)

    stack = [(top_b, "")]
    while stack:
        dir_b, rel = stack.pop()
        with os.scandir(dir_b) as it:
            children = sorted(it, key=lambda d: d.name)
        for d in children:
            name = _name(d.name, join(mountpoint, rel) or "/")
            crel = f"{rel}/{name}" if rel else name
            st = os.lstat(d.path)
            if stat.S_ISDIR(st.st_mode) and st.st_dev != root_dev:
                # Something else is mounted here; it is not part of this
                # filesystem. Record the directory, not its contents.
                yield join(mountpoint, crel), entry_for(d.path, crel, os.lstat(d.path))
                continue
            yield join(mountpoint, crel), entry_for(d.path, crel, st)
            if stat.S_ISDIR(st.st_mode):
                stack.append((d.path, crel))


def build(mounts, source=None, created=None):
    """mounts: list of (mountpoint, dir, posix). Returns the manifest dict."""
    mps = [m[0] for m in mounts]
    if "/" not in mps:
        raise ManifestError("a mount for / is required")
    if len(set(mps)) != len(mps):
        raise ManifestError("each mountpoint may be given once")

    by_path = {}
    shadowed = []
    # Shorter mountpoints first, so a filesystem mounted on /boot replaces the
    # root filesystem's (normally empty) /boot directory.
    for mp, d, posix in sorted(mounts, key=lambda m: len(m[0])):
        for p in list(by_path):
            if under(p, mp):
                shadowed.append(p)
                del by_path[p]
        for path, e in walk_mount(mp, d, posix):
            by_path[path] = e

    entries = [by_path[p] for p in sorted(by_path)]
    counts = {}
    total = 0
    for e in entries:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
        total += e.get("size", 0)

    root_dir = dict(mounts_by_mp(mounts))["/"]
    return {
        "schema": SCHEMA,
        "generator": GENERATOR,
        "created": created or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": dict(sorted((source or {}).items())),
        "build_info": parse_kv_file(os.path.join(root_dir, "etc/nodetrust/build-info")),
        "filesystems": [{"mount": mp, "posix": posix} for mp, _, posix in sorted(mounts)],
        "stats": {"entries": len(entries), "by_type": counts, "file_bytes": total, "shadowed": len(shadowed)},
        "shadowed": sorted(shadowed),
        "entries_sha256": entries_digest(entries),
        "entries": entries,
    }


def mounts_by_mp(mounts):
    return [(mp, d) for mp, d, _ in mounts]


# --- path resolution over the manifest ---------------------------------------


def resolve(index, path, max_links=40):
    """Resolve symlinks in an image path using manifest entries only.

    Returns the final path (which may not exist in the manifest) or None on a
    symlink loop.
    """
    parts = [p for p in path.split("/") if p]
    done = []
    links = 0
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            if done:
                done.pop()
            continue
        cur = "/" + "/".join(done + [part])
        e = index.get(cur)
        if e is not None and e["type"] == "symlink":
            links += 1
            if links > max_links:
                return None
            t = e["target"]
            tparts = [p for p in t.split("/") if p]
            if t.startswith("/"):
                done = []
            parts = tparts + parts
            continue
        done.append(part)
    return "/" + "/".join(done)


def host_path(mounts, image_path):
    """Map an image path to the host path under the longest matching mount."""
    best = None
    for mp, d in mounts:
        if image_path == mp or under(image_path, mp):
            if best is None or len(mp) > len(best[0]):
                best = (mp, d)
    mp, d = best
    rel = image_path[len(mp):].lstrip("/") if mp != "/" else image_path.lstrip("/")
    return os.path.join(d, rel)


# --- dpkg cross-check ---------------------------------------------------------


def read_diversions(root_dir):
    """dpkg diversions: {original path: (diverted-to path, owning package)}.

    The owning package's own copy stays at the original path; the same file
    from any other package is installed at the diverted-to path. The owner
    "LOCAL" (a manual diversion) means every package is diverted.
    """
    out = {}
    try:
        with open(os.path.join(root_dir, "var/lib/dpkg/diversions"), encoding="utf-8") as f:
            lines = [ln.rstrip("\n") for ln in f]
    except FileNotFoundError:
        return out
    for i in range(0, len(lines) - 2, 3):
        out[lines[i]] = (lines[i + 1], lines[i + 2])
    return out


def read_md5sums(root_dir):
    """Yield (package, image_path, md5) from every *.md5sums file."""
    info = os.path.join(root_dir, "var/lib/dpkg/info")
    for name in sorted(os.listdir(info)):
        if not name.endswith(".md5sums"):
            continue
        pkg = name[: -len(".md5sums")]
        with open(os.path.join(info, name), "rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\n")
                if not raw:
                    continue
                md5, _, rel = raw.partition(b"  ")
                yield pkg, "/" + rel.decode("utf-8", "surrogateescape"), md5.decode()


def check_dpkg(manifest, mounts):
    """Compare dpkg's recorded md5 of every packaged file with the file read
    from the image, and that file's SHA-256 with the manifest.

    Returns a dict of counts and example problems.
    """
    index = {e["path"]: e for e in manifest["entries"]}
    root_dir = dict(mounts)["/"]
    diversions = read_diversions(root_dir)
    res = {"checked": 0, "missing": [], "md5_mismatch": [], "sha_mismatch": [], "diverted": 0}
    seen = set()
    for pkg, path, md5 in read_md5sums(root_dir):
        div = diversions.get(path)
        if div is not None and pkg.split(":", 1)[0] != div[1]:
            # This package's copy was installed at the diverted-to path.
            path = div[0]
            res["diverted"] += 1
        real = resolve(index, path)
        e = index.get(real) if real else None
        if e is None or e["type"] != "file":
            res["missing"].append(f"{pkg}: {path}")
            continue
        if real in seen:
            # Same file listed by two packages (or via /bin and /usr/bin).
            continue
        seen.add(real)
        got_md5, got_sha = hash_file(host_path(mounts, real), ("md5", "sha256"))
        res["checked"] += 1
        if got_md5 != md5:
            res["md5_mismatch"].append(f"{pkg}: {real}")
        if got_sha != e["sha256"]:
            res["sha_mismatch"].append(real)
    return res


# --- statement (step 2.2) -----------------------------------------------------


def make_statement(gz_bytes, ami, snapshot, region, uri, key_id, signed_at=None):
    """Build the statement that binds an AMI to a manifest. Returns its bytes.

    The signature covers these exact bytes (compact JSON, sorted keys, no
    trailing newline). Refuses a manifest whose entries do not match its
    entries_sha256 or that was built from a different AMI or snapshot.
    """
    raw = gzip.decompress(gz_bytes)
    m = json.loads(raw.decode("utf-8"))
    if m.get("schema") != SCHEMA:
        raise ManifestError(f"manifest schema {m.get('schema')!r}, want {SCHEMA!r}")
    if entries_digest(m["entries"]) != m["entries_sha256"]:
        raise ManifestError("manifest entries do not match its entries_sha256")
    src = m["source"]
    if (src.get("ami_id"), src.get("snapshot_id"), src.get("region")) != (ami, snapshot, region):
        raise ManifestError(
            f"manifest was built from {src.get('ami_id')}/{src.get('snapshot_id')} in {src.get('region')}, "
            f"not {ami}/{snapshot} in {region}")
    st = {
        "schema": STATEMENT_SCHEMA,
        "ami_id": ami,
        "snapshot_id": snapshot,
        "region": region,
        "manifest_uri": uri,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_gz_sha256": hashlib.sha256(gz_bytes).hexdigest(),
        "entries_sha256": m["entries_sha256"],
        "build_info": m["build_info"],
        "key_id": key_id,
        "signed_at": signed_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return canonical(st)


# --- CLI ----------------------------------------------------------------------


def cmd_build(a):
    mounts = [parse_mount(s) for s in a.mount]
    source = {}
    for kv in a.meta or []:
        if "=" not in kv:
            raise ManifestError(f"bad --meta {kv!r}; want KEY=VALUE")
        k, v = kv.split("=", 1)
        source[k] = v
    m = build(mounts, source, a.created)
    data = json.dumps(m, sort_keys=True, indent=1, ensure_ascii=False).encode("utf-8") + b"\n"
    with open(a.output, "wb") as f:
        f.write(data)
    s = m["stats"]
    print(f"entries={s['entries']} files={s['by_type'].get('file', 0)} bytes={s['file_bytes']} "
          f"shadowed={s['shadowed']} entries_sha256={m['entries_sha256']}")
    return 0


def cmd_digest(a):
    m = open_manifest(a.manifest)
    if m.get("schema") != SCHEMA:
        print(f"unknown schema {m.get('schema')!r}", file=sys.stderr)
        return 1
    got = entries_digest(m["entries"])
    ok = got == m["entries_sha256"]
    if a.quiet:
        print(got)
    else:
        s = m["stats"]
        print(f"schema          {m['schema']}")
        print(f"created         {m['created']}")
        for k, v in m["source"].items():
            print(f"source.{k:<9} {v}")
        for k, v in m["build_info"].items():
            print(f"build.{k:<10} {v}")
        print(f"entries         {s['entries']} {json.dumps(s['by_type'], sort_keys=True)}")
        print(f"file bytes      {s['file_bytes']}")
        print(f"entries_sha256  {m['entries_sha256']}")
        print(f"recomputed      {got} ({'match' if ok else 'MISMATCH'})")
    return 0 if ok else 1


def cmd_find(a):
    m = open_manifest(a.manifest)
    n = 0
    for e in m["entries"]:
        if fnmatch.fnmatchcase(e["path"], a.pattern):
            n += 1
            print(f"{e.get('sha256', e['type'])}  {e['path']}")
    return 0 if n else 1


def cmd_check_dpkg(a):
    m = open_manifest(a.manifest)
    mounts = [parse_mount(s)[:2] for s in a.mount]
    r = check_dpkg(m, mounts)
    print(f"checked={r['checked']} diverted={r['diverted']} missing={len(r['missing'])} "
          f"md5_mismatch={len(r['md5_mismatch'])} sha_mismatch={len(r['sha_mismatch'])}")
    for k in ("missing", "md5_mismatch", "sha_mismatch"):
        for x in r[k][: a.show]:
            print(f"  {k}: {x}")
        if len(r[k]) > a.show:
            print(f"  {k}: ... {len(r[k]) - a.show} more")
    return 0 if not (r["missing"] or r["md5_mismatch"] or r["sha_mismatch"]) else 1


def cmd_statement(a):
    with open(a.manifest, "rb") as f:
        gz = f.read()
    st = make_statement(gz, a.ami, a.snapshot, a.region, a.uri, a.key_id, a.signed_at)
    with open(a.output, "wb") as f:
        f.write(st)
    print(f"statement {len(st)} bytes sha256={hashlib.sha256(st).hexdigest()}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build")
    b.add_argument("--mount", action="append", required=True, metavar="MP=DIR[:nonposix]")
    b.add_argument("--meta", action="append", metavar="KEY=VALUE")
    b.add_argument("--created", help="fixed timestamp (default: now)")
    b.add_argument("-o", "--output", required=True)
    b.set_defaults(fn=cmd_build)

    d = sub.add_parser("digest")
    d.add_argument("manifest")
    d.add_argument("--quiet", action="store_true", help="print only the recomputed digest")
    d.set_defaults(fn=cmd_digest)

    f = sub.add_parser("find")
    f.add_argument("manifest")
    f.add_argument("pattern")
    f.set_defaults(fn=cmd_find)

    c = sub.add_parser("check-dpkg")
    c.add_argument("manifest")
    c.add_argument("--mount", action="append", required=True, metavar="MP=DIR[:nonposix]")
    c.add_argument("--show", type=int, default=20)
    c.set_defaults(fn=cmd_check_dpkg)

    st = sub.add_parser("statement")
    st.add_argument("--manifest", required=True, help="manifest.json.gz")
    st.add_argument("--ami", required=True)
    st.add_argument("--snapshot", required=True)
    st.add_argument("--region", required=True)
    st.add_argument("--uri", required=True, help="where the manifest is stored")
    st.add_argument("--key-id", required=True, help="KMS key ARN")
    st.add_argument("--signed-at")
    st.add_argument("-o", "--output", required=True)
    st.set_defaults(fn=cmd_statement)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
