#!/usr/bin/env python3
"""
aptrepo.py - Private APT repository manager

Features:
  - Multiple versions of the same package per dist
  - Per-dist pool directories (like freight)
  - Debian-style pool layout: pool/<dist>/<component>/<prefix>/<source>/
  - Multiple dists, components, architectures per repo
  - YAML config with defaults + per-dist overrides
  - GPG signing via gpg agent
  - Static browsable HTML index with live Packages parsing

Usage:
  aptrepo.py init
  aptrepo.py add              <dist> [-C <component>] <file.deb> [file.deb ...]
  aptrepo.py remove           <dist> <package> <version> [<arch>]
  aptrepo.py update           [<dist>]
  aptrepo.py list             [<dist>]
  aptrepo.py ingest           [<incoming_dir>]
  aptrepo.py prune            <n> [options]
"""

import argparse
import functools
import gzip
import io
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import apt_inst
import apt_pkg
import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REWRITE_ORDER = apt_pkg.REWRITE_PACKAGE_ORDER

# Fields to strip from the .deb control before writing to the Packages index.
# We'll add them back ourselves (Filename, Size, hashes).
_STRIP_FIELDS = {"Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512"}

# Identifier charsets per Debian policy.  Deliberately strict: these values end
# up in filesystem paths and index files, so anything outside these patterns is
# rejected to prevent path traversal and index corruption.
_PKG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")          # package / source name
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:-]*$")  # epoch:upstream-revision
_ARCH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")            # amd64, arm64, all, ...


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def die(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str):
    print(f"WARNING: {msg}", file=sys.stderr)


def _is_safe_basename(name: str) -> bool:
    """True if *name* is a plain filename (no path separators, no traversal)."""
    if not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name:
        return False
    if name != os.path.basename(name):
        return False
    return True


def validate_deb_identifiers(package: str, source: str,
                             version: str, arch: str):
    """Validate identifiers extracted from a .deb control file.

    These values are used to build filesystem paths and repository index
    entries, so they must be strictly validated.  Raises ValueError on any
    value that does not conform to Debian policy character sets (which, among
    other things, makes path traversal impossible).
    """
    if not _PKG_NAME_RE.match(package):
        raise ValueError(f"Invalid package name: {package!r}")
    if not _PKG_NAME_RE.match(source):
        raise ValueError(f"Invalid source name: {source!r}")
    if not _VERSION_RE.match(version):
        raise ValueError(f"Invalid version string: {version!r}")
    if not _ARCH_RE.match(arch):
        raise ValueError(f"Invalid architecture: {arch!r}")


def _file_sha256(path: Path) -> str | None:
    """Return the SHA256 hex digest of *path*, or None if unavailable."""
    with open(path, "rb") as f:
        hashes = apt_pkg.Hashes(f)
    return next(
        (h.hashvalue for h in hashes.hashes if h.hashtype == "SHA256"),
        None,
    )


def _move_to(src: Path, dest_dir: Path):
    """Move a file to dest_dir, appending a timestamp if name already exists."""
    dest = dest_dir / src.name
    if dest.exists():
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = dest_dir / f"{src.stem}.{ts}{src.suffix}"
    shutil.move(str(src), dest)


def _atomic_replace(tmp: str, dest: Path):
    """Set the correct mode on *tmp*, then atomically rename it onto *dest*.

    tempfile.mkstemp() always creates files as 0600, and os.replace() keeps
    the tempfile's mode -- which would leave published files unreadable by the
    web server (which usually runs as a different user).  So we apply the mode
    a normal create would produce under the current umask (e.g. 0644 with the
    usual umask of 022).  os.umask() is the only way to read the umask: it sets
    and returns the previous value, so we set-and-restore. Safe here as the
    script is single-threaded.
    """
    umask = os.umask(0)
    os.umask(umask)
    os.chmod(tmp, 0o666 & ~umask)
    os.replace(tmp, dest)


def _atomic_write(dest: Path, data: bytes):
    """Write *data* to *dest* atomically using a tempfile + rename."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _atomic_replace(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------
# Path helpers

def pool_prefix(source_name: str) -> str:
    """Return the first-level pool prefix for a source package name.

    Mirrors Debian upstream behaviour:
      lib* packages  -> first 4 characters  (libc, libp, liba, lib3, …)
      everything else -> first character
    """
    if source_name.startswith("lib") and len(source_name) >= 4:
        return source_name[:4]
    return source_name[0]


def pool_dir(base_dir: Path, dist: str, component: str) -> Path:
    """Directory holding a dist+component's pool (parent of the prefix dirs)."""
    return base_dir / "pool" / dist / component


def pool_path(base_dir: Path, dist: str, component: str,
              source_name: str, filename: str) -> Path:
    """Absolute path for a .deb inside the pool."""
    prefix = pool_prefix(source_name)
    return pool_dir(base_dir, dist, component) / prefix / source_name / filename


def dists_path(base_dir: Path, dist: str) -> Path:
    return base_dir / "dists" / dist


def packages_path(base_dir: Path, dist: str, component: str, arch: str) -> Path:
    return dists_path(base_dir, dist) / component / f"binary-{arch}"


# ---------------------------------------------
# .deb metadata extraction

def read_deb(deb_path: Path) -> dict:
    """Extract control fields + file hashes from a .deb.  Returns a dict."""
    deb = apt_inst.DebFile(str(deb_path))
    ctrl_bytes = deb.control.extractdata("control")
    ctrl_text = ctrl_bytes.decode("utf-8", errors="replace")
    section = apt_pkg.TagSection(ctrl_text)

    package = section["Package"]
    version = section["Version"]
    arch = section["Architecture"]

    # Source name (may be "srcname (binversion)", we want just the name).
    # Fall back to the package name if Source is absent or empty.
    raw_src = (section.get("Source") or package).split()
    source_name = raw_src[0] if raw_src else package

    # Reject anything that does not conform to Debian policy.  These values are
    # used to build filesystem paths, so this also prevents path traversal.
    validate_deb_identifiers(package, source_name, version, arch)

    # Hashes
    with open(deb_path, "rb") as f:
        hashes = apt_pkg.Hashes(f)

    hash_map = {}
    size = None
    for hs in hashes.hashes:
        if hs.hashtype == "MD5Sum":
            hash_map["MD5sum"] = hs.hashvalue
        elif hs.hashtype == "SHA1":
            hash_map["SHA1"] = hs.hashvalue
        elif hs.hashtype == "SHA256":
            hash_map["SHA256"] = hs.hashvalue
        elif hs.hashtype == "SHA512":
            hash_map["SHA512"] = hs.hashvalue
        elif hs.hashtype == "Checksum-FileSize":
            size = hs.hashvalue

    if size is None:
        size = os.path.getsize(deb_path)

    return {
        "ctrl_text": ctrl_text,
        "package": package,
        "version": version,
        "arch": arch,
        "source": source_name,
        "size": size,
        "hashes": hash_map,
    }


# ---------------------------------------------
# Packages index building

def build_packages_entry(meta: dict, filename_rel: str) -> bytes:
    """Produce one stanza for a Packages index file."""
    ctrl_text = meta["ctrl_text"]

    # Parse a fresh TagSection from the stored control text.
    section = apt_pkg.TagSection(ctrl_text)

    rewrites = [
        apt_pkg.TagRewrite("Filename", filename_rel),
        apt_pkg.TagRewrite("Size", str(meta["size"])),
    ]
    for field, value in meta["hashes"].items():
        rewrites.append(apt_pkg.TagRewrite(field, value))

    # Strip any pre-existing hash/size/filename fields from the control data
    for field in _STRIP_FIELDS:
        if field in section:
            rewrites.append(apt_pkg.TagRemove(field))

    with tempfile.TemporaryFile() as f:
        section.write(f, REWRITE_ORDER, rewrites)
        f.seek(0)
        return f.read()


def write_packages_index(entries: list[bytes], dest_dir: Path):
    """Write Packages, Packages.gz, Packages.xz to dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    raw = b"\n".join(entries) + b"\n"

    buf_io = io.BytesIO()
    with gzip.GzipFile(fileobj=buf_io, mode="wb", mtime=0) as g:
        g.write(raw)
    gz_data = buf_io.getvalue()

    xz_data = lzma.compress(raw, format=lzma.FORMAT_XZ)

    _atomic_write(dest_dir / "Packages", raw)
    _atomic_write(dest_dir / "Packages.gz", gz_data)
    _atomic_write(dest_dir / "Packages.xz", xz_data)


# ---------------------------------------------
# Pool management

def add_to_pool(base_dir: Path, dist: str, component: str,
                meta: dict, src_path: Path) -> Path:
    """Copy .deb into the pool (if not already identical). Returns pool path."""
    dest = pool_path(base_dir, dist, component,
                     meta["source"], src_path.name)
    if dest.exists():
        # Check if it's identical by SHA256
        existing_sha256 = _file_sha256(dest)
        if existing_sha256 == meta["hashes"].get("SHA256"):
            print(f"  [pool] Already present (identical): {dest.relative_to(base_dir)}")
            return dest
        else:
            die(
                f"Pool collision: {dest.relative_to(base_dir)} exists with "
                f"different content.\n"
                f"  existing SHA256: {existing_sha256}\n"
                f"  new      SHA256: {meta['hashes'].get('SHA256')}\n"
                f"Bump the package version to resolve this."
            )
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dest)
    print(f"  [pool] Added: {dest.relative_to(base_dir)}")
    return dest


def scan_pool(base_dir: Path, dist: str, component: str) -> list[dict]:
    """Scan the pool for a given dist+component, return list of metadata dicts."""
    pdir = pool_dir(base_dir, dist, component)
    if not pdir.exists():
        return []

    entries = []
    for deb_path in sorted(pdir.rglob("*.deb")):
        try:
            meta = read_deb(deb_path)
            meta["pool_path"] = deb_path
            entries.append(meta)
        except Exception as e:
            warn(f"Could not read {deb_path}: {e}")
    return entries


def remove_pool_file(pool_path: Path):
    """Remove a single .deb from the pool and tidy up emptied directories.

    Walks up the pool/<dist>/<component>/<prefix>/<source>/ layout removing the
    source, prefix, and component directories if (and only if) they are empty.
    """
    pool_path.unlink()
    for parent in (pool_path.parent,
                   pool_path.parent.parent,
                   pool_path.parent.parent.parent):
        try:
            parent.rmdir()
        except OSError:
            break


# ---------------------------------------------
# Release file generation

def _hash_file(path: Path) -> dict:
    with open(path, "rb") as f:
        hashes = apt_pkg.Hashes(f)
    result = {"size": os.path.getsize(path)}
    for hs in hashes.hashes:
        if hs.hashtype == "MD5Sum":
            result["md5"] = hs.hashvalue
        elif hs.hashtype == "SHA1":
            result["sha1"] = hs.hashvalue
        elif hs.hashtype == "SHA256":
            result["sha256"] = hs.hashvalue
        elif hs.hashtype == "SHA512":
            result["sha512"] = hs.hashvalue
    return result


def build_release(base_dir: Path, dist_cfg: dict):
    """Write the Release file for a dist, collecting hashes of all index files."""
    dist = dist_cfg["name"]
    dist_dir = dists_path(base_dir, dist)

    # Collect all index files we need to hash
    index_files = []
    for component in dist_cfg["components"]:
        for arch in dist_cfg["architectures"]:
            pkg_dir = dist_dir / component / f"binary-{arch}"
            for fname in ("Packages", "Packages.gz", "Packages.xz"):
                fpath = pkg_dir / fname
                if fpath.exists():
                    index_files.append(fpath)

    # Build hash sections
    md5_lines = []
    sha1_lines = []
    sha256_lines = []
    sha512_lines = []
    for fpath in index_files:
        rel = fpath.relative_to(dist_dir)
        info = _hash_file(fpath)
        size = info["size"]
        md5_lines.append(f" {info['md5']} {size:>16} {rel}")
        sha1_lines.append(f" {info['sha1']} {size:>16} {rel}")
        sha256_lines.append(f" {info['sha256']} {size:>16} {rel}")
        sha512_lines.append(f" {info['sha512']} {size:>16} {rel}")

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S +0000")

    lines = []
    lines.append(f"Origin: {dist_cfg.get('origin') or dist}")
    lines.append(f"Label: {dist_cfg.get('label') or dist}")
    lines.append(f"Suite: {dist_cfg.get('suite') or dist}")
    lines.append(f"Codename: {dist}")
    if dist_cfg.get("description"):
        lines.append(f"Description: {dist_cfg['description']}")
    lines.append(f"Date: {date_str}")
    lines.append(f"Architectures: {' '.join(dist_cfg['architectures'])}")
    lines.append(f"Components: {' '.join(dist_cfg['components'])}")
    lines.append("MD5Sum:")
    lines.extend(md5_lines)
    lines.append("SHA1:")
    lines.extend(sha1_lines)
    lines.append("SHA256:")
    lines.extend(sha256_lines)
    lines.append("SHA512:")
    lines.extend(sha512_lines)

    release_path = dist_dir / "Release"
    dist_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(release_path, ("\n".join(lines) + "\n").encode())
    print(f"  [release] Written: {release_path.relative_to(base_dir)}")
    return release_path


# ---------------------------------------------
# GPG signing

def _run_gpg(cmd: list):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        die(
            f"GPG failed (exit {result.returncode}):\n"
            + result.stderr.decode(errors="replace")
        )

def _gpg_sign(release_path: Path, dest: Path, key_id: str, sign_flag: str):
    """Sign *release_path* with gpg, writing the signature atomically to *dest*.

    *sign_flag* selects the signature kind: "--detach-sign" for Release.gpg or
    "--clearsign" for InRelease.  gpg writes to a tempfile in the destination
    directory which is then atomically renamed into place; the tempfile is
    cleaned up if anything fails.
    """
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
    os.close(fd)
    try:
        cmd = ["gpg", "--batch", "--yes", "--armor", sign_flag]
        if key_id:
            cmd += ["--local-user", key_id]
        cmd += ["--output", tmp, str(release_path)]
        _run_gpg(cmd)
        _atomic_replace(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    print(f"  [sign] {dest.name}")


def sign_release(release_path: Path, key_id: str):
    """Produce Release.gpg (detached) and InRelease (clearsigned)."""
    base = release_path.parent
    _gpg_sign(release_path, base / "Release.gpg", key_id, "--detach-sign")
    _gpg_sign(release_path, base / "InRelease", key_id, "--clearsign")


# ---------------------------------------------
# update dist

def update_dist(cfg: dict, dist_name: str):
    """Regenerate Packages indices and Release file for one dist."""
    dist_cfg = cfg["dists"][dist_name]
    base_dir = cfg["base_dir"]

    print(f"\nUpdating dist: {dist_name}")

    for component in dist_cfg["components"]:
        entries_by_arch: dict[str, list[bytes]] = {
            arch: [] for arch in dist_cfg["architectures"]
        }

        pool_entries = scan_pool(base_dir, dist_name, component)
        for meta in pool_entries:
            deb_path = meta["pool_path"]
            # Relative filename from repo root for the Packages index
            filename_rel = str(deb_path.relative_to(base_dir))

            entry_bytes = build_packages_entry(meta, filename_rel)

            target_arches = (
                dist_cfg["architectures"]
                if meta["arch"] == "all"
                else [meta["arch"]]
            )
            for arch in target_arches:
                if arch in entries_by_arch:
                    entries_by_arch[arch].append(entry_bytes)

        for arch, entries in entries_by_arch.items():
            # Sort entries by package name then version for deterministic output
            entries.sort(key=_entry_sort_key)
            pkg_dir = packages_path(base_dir, dist_name, component, arch)
            write_packages_index(entries, pkg_dir)
            print(f"  [index] {component}/binary-{arch}: {len(entries)} package(s)")

    release_path = build_release(base_dir, dist_cfg)

    key_id = dist_cfg.get("sign_with")
    if key_id:
        sign_release(release_path, key_id)
    else:
        # Remove stale signature files if signing is disabled
        for fname in ("Release.gpg", "InRelease"):
            stale = release_path.parent / fname
            if stale.exists():
                stale.unlink()
        print("  [sign] Skipped (no sign_with configured)")


def _entry_sort_key(entry: bytes) -> tuple:
    """Sort key for Packages entries: (package_name, version)."""
    try:
        section = apt_pkg.TagSection(entry.decode("utf-8", errors="replace"))
        return (section.get("Package", ""), section.get("Version", ""))
    except Exception:
        return ("", "")


# ---------------------------------------------
# Signature verification (Sequoia-PGP via the pysequoia bindings)

def _import_pysequoia():
    """Import pysequoia lazily so commands that don't verify signatures
    (init, add, remove, update, list, prune) work without the dependency.

    Returns the (Cert, verify) pair. Raises a clear error if unavailable.
    """
    try:
        from pysequoia import Cert, verify
    except ImportError as e:
        die(
            "The 'ingest' command requires the pysequoia library for signature "
            "verification, but it could not be imported.\n"
            "Install it with:  apt install python3-pysequoia   (Debian trixie+, "
            "Ubuntu 26.04+)\n"
            f"Import error: {e}"
        )
    return Cert, verify


def load_signer_certs(keyring: Path) -> list:
    """Load all OpenPGP certificates (public keys) from the signer keyring.

    *keyring* may be a single file (possibly containing several certs) or a
    directory of cert files.  Returns a list of pysequoia Cert objects.
    """
    Cert, _ = _import_pysequoia()

    if not keyring.exists():
        die(f"signer_keyring path does not exist: {keyring}")

    files = []
    if keyring.is_dir():
        files = [p for p in sorted(keyring.iterdir()) if p.is_file()]
    else:
        files = [keyring]

    certs = []
    for path in files:
        try:
            certs.extend(Cert.split_file(str(path)))
        except Exception as e:
            warn(f"Could not load certificates from {path}: {e}")

    if not certs:
        die(
            f"No certificates found in signer_keyring: {keyring}\n"
            f"Export your build servers' public keys there, e.g.:\n"
            f"  gpg --armor --export <key-id> > {keyring}/buildserver.asc"
        )
    return certs


def verify_changes_signature(changes_path: Path, certs: list) -> tuple[list[str], bytes]:
    """Cryptographically verify the signature on a (clearsigned) .changes file.

    Verification is delegated entirely to Sequoia-PGP: it succeeds only if the
    file carries at least one valid signature made by one of the supplied
    *certs*.  Tampered, unsigned, truncated, or unknown-key inputs all cause
    Sequoia to raise, which we translate into a ValueError.

    Returns a tuple of:
      - the list of certificate (primary key) fingerprints that produced a
        valid signature, uppercased
      - the verified payload bytes (the clear-text content of the .changes)

    Note: authorisation (is this signer allowed for this dist?) is NOT decided
    here -- the caller checks the returned fingerprints against the dist's
    allowed_signers after parsing the verified payload.
    """
    _, verify = _import_pysequoia()

    raw = changes_path.read_bytes()

    # The store callback is handed the key IDs referenced by the signature(s);
    # we simply offer every known cert and let Sequoia pick. Returning more
    # certs than necessary is explicitly allowed.
    def store(_key_ids):
        return certs

    try:
        result = verify(bytes=raw, store=store)
    except Exception as e:
        # Sequoia raises on bad/missing/unknown/truncated signatures. Collapse
        # its (verbose, backtrace-laden) error into a single concise line.
        detail = str(e).splitlines()[0] if str(e) else e.__class__.__name__
        raise ValueError(
            f"Signature verification failed for {changes_path.name}: {detail}"
        ) from e

    valid_fingerprints = [s.certificate.upper() for s in result.valid_sigs]
    if not valid_fingerprints:
        # Defensive: current pysequoia raises rather than returning an empty
        # list, but never trust an unsigned/empty result.
        raise ValueError(
            f"Signature verification failed for {changes_path.name}: "
            f"no valid signatures."
        )

    return valid_fingerprints, result.bytes


def _normalise_keyid(keyid: str) -> str:
    """Strip a leading 0x/0X prefix and uppercase the key id."""
    k = keyid.strip()
    if k[:2].lower() == "0x":
        k = k[2:]
    return k.upper()


def _fingerprint_matches(fingerprint: str, allowed_keyids: list[str]) -> bool:
    """Return True if *fingerprint* matches any entry in *allowed_keyids*.

    Fingerprint is a full 40-char hex string (from VALIDSIG).
    Entries in allowed_keyids may be:
      - Full fingerprint (40 hex chars)
      - Long key ID     (16 hex chars)
      - Short key ID    ( 8 hex chars)  -- accepted but insecure
    All comparisons are suffix-based so long/short IDs work naturally.
    Leading "0x" prefixes in configured key IDs are stripped automatically.
    """
    fp = fingerprint.strip().upper()
    for kid in allowed_keyids:
        kid_norm = _normalise_keyid(kid)
        if not kid_norm:
            continue
        if fp.endswith(kid_norm):
            return True
    return False


# ---------------------------------------------
# .changes file parsing

def _parse_hash_field(field_value: str) -> dict[str, dict]:
    """Parse a multi-line Checksums-* or Files field into {filename: {hash/size}}."""
    result = {}
    for line in field_value.strip().splitlines():
        parts = line.split()
        if len(parts) == 3:
            # Checksums-Sha1/Sha256/Sha512: <hash> <size> <filename>
            hashval, size, fname = parts
            result.setdefault(fname, {})["size"] = int(size)
            result[fname]["hash"] = hashval
        elif len(parts) == 5:
            # Files: <md5> <size> <section> <priority> <filename>
            md5, size, section, _priority, fname = parts
            result.setdefault(fname, {})["size"] = int(size)
            result[fname]["md5"] = md5
            result[fname]["section"] = section
    return result


def parse_changes(payload: bytes) -> dict:
    """Parse the verified payload of a .changes file.

    *payload* must be the clear-text content that Sequoia returned from
    signature verification -- NOT the raw clearsigned file.  Parsing only
    verified bytes guarantees we never act on data that wasn't signed.

    Returns a dict with keys:
      distribution, source, version, files
    Where files is a list of dicts:
      {filename, size, sha256, sha1, md5, component, section}
    """
    # Parse via TagFile (handles multi-line fields correctly)
    with tempfile.NamedTemporaryFile(suffix=".changes", delete=False) as tf:
        tf.write(payload)
        tf_name = tf.name
    try:
        with open(tf_name) as f:
            tag_file = apt_pkg.TagFile(f)
            tag_file.step()
            section = tag_file.section
    finally:
        os.unlink(tf_name)

    distribution = section["Distribution"].strip()
    source = section["Source"].strip()
    version = section["Version"].strip()

    # Gather hashes from all available checksum fields
    sha256_map = _parse_hash_field(section.get("Checksums-Sha256", ""))
    sha1_map = _parse_hash_field(section.get("Checksums-Sha1", ""))
    files_map = _parse_hash_field(section.get("Files", ""))

    # Build unified file list from Files: (it has the section/component info)
    # Fall back to Checksums-Sha256 keys if Files is absent
    all_filenames = set(files_map) | set(sha256_map)

    files = []
    for fname in sorted(all_filenames):
        if not fname.endswith(".deb"):
            # Skip .dsc, .tar.*, .buildinfo etc.
            continue
        # Defence in depth: filenames from the .changes are used to locate
        # files on disk, so reject anything that is not a plain basename.
        if not _is_safe_basename(fname):
            raise ValueError(f"Unsafe filename in .changes: {fname!r}")
        raw_section = files_map.get(fname, {}).get("section", "")
        if "/" in raw_section:
            component, sec = raw_section.split("/", 1)
        else:
            component = "main"
            sec = raw_section

        entry = {
            "filename":  fname,
            "size":      files_map.get(fname, sha256_map.get(fname, {})).get("size"),
            "sha256":    sha256_map.get(fname, {}).get("hash"),
            "sha1":      sha1_map.get(fname, {}).get("hash"),
            "md5":       files_map.get(fname, {}).get("md5"),
            "component": component,
            "section":   sec,
        }
        files.append(entry)

    return {
        "distribution": distribution,
        "source":       source,
        "version":      version,
        "files":        files,
    }


def verify_changes_files(changes_info: dict, incoming_dir: Path) -> list[Path]:
    """Check all .deb files referenced by a .changes exist and have correct checksums.

    Returns the list of verified .deb Paths.
    Raises ValueError listing all problems found (checks everything before raising).
    """
    errors = []
    verified = []

    for entry in changes_info["files"]:
        fname = entry["filename"]
        deb_path = incoming_dir / fname

        if not deb_path.exists():
            errors.append(f"  Missing file: {fname}")
            continue

        actual_size = deb_path.stat().st_size
        if entry["size"] is not None and actual_size != entry["size"]:
            errors.append(
                f"  Size mismatch for {fname}: "
                f"expected {entry['size']}, got {actual_size}"
            )
            continue  # don't bother hashing a wrong-sized file

        # Verify SHA256 if present (preferred), fall back to MD5
        if entry.get("sha256"):
            actual_sha256 = _file_sha256(deb_path)
            if actual_sha256 != entry["sha256"]:
                errors.append(
                    f"  SHA256 mismatch for {fname}: "
                    f"expected {entry['sha256']}, got {actual_sha256}"
                )
                continue
        elif entry.get("md5"):
            with open(deb_path, "rb") as f:
                actual_md5 = hashlib.md5(f.read()).hexdigest()
            if actual_md5 != entry["md5"]:
                errors.append(
                    f"  MD5 mismatch for {fname}: "
                    f"expected {entry['md5']}, got {actual_md5}"
                )
                continue

        verified.append(deb_path)

    if errors:
        raise ValueError(
            f"File verification failed for {changes_info['source']}:\n"
            + "\n".join(errors)
        )

    return verified


# ---------------------------------------------
# Repo metadata

def build_repo_json(cfg: dict) -> dict:
    """Build the repo.json structure from the loaded config."""
    dists_out = {}
    for name, dist_cfg in cfg["dists"].items():
        dists_out[name] = {
            "components":    dist_cfg["components"],
            "architectures": dist_cfg["architectures"],
            "description":   dist_cfg.get("description") or "",
        }
    return {"dists": dists_out}


def write_repo_metadata(cfg: dict):
    """Write repo.json to the repo base directory.

    repo.json describes the dist/component/architecture structure of the repo
    and is consumed by the static browser index (index.html) served by nginx.
    """
    base_dir = cfg["base_dir"]
    base_dir.mkdir(parents=True, exist_ok=True)

    repo_json_path = base_dir / "repo.json"
    repo_data = build_repo_json(cfg)
    _atomic_write(repo_json_path, (json.dumps(repo_data, indent=2, ensure_ascii=False) + "\n").encode())
    print(f"  [meta] Written: repo.json")


def _regenerate(cfg: dict, dist_names):
    """Rebuild indices + Release for each unique dist, then write metadata once.

    This is the common tail of every command that mutates the repo (add,
    remove, update, ingest, prune): each affected dist is rebuilt and the
    repo.json metadata is refreshed afterwards.
    """
    for dist_name in sorted(set(dist_names)):
        update_dist(cfg, dist_name)
    write_repo_metadata(cfg)


# ---------------------------------------------------------------------------
# configuration management
# ---------------------------------------------------------------------------

CONFIG_DEFAULTS = {
    "components": ["main"],
    "architectures": ["amd64"],
    "sign_with": None,          # GPG key-id, or None to skip signing
    "suite": None,              # falls back to dist name if None
    "label": None,
    "origin": None,
    "description": None,
    "allowed_signers": [],      # list of GPG key-ids allowed to sign .changes files
}


def _load_raw_config(path: Path) -> dict:
    """Read and parse the YAML config, validating the required top-level keys."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    if "repo" not in raw:
        die("Config must have a top-level 'repo' section.")
    if "dists" not in raw:
        die("Config must have a top-level 'dists' section.")
    if "base_dir" not in raw["repo"]:
        die("Config 'repo.base_dir' is required.")
    return raw


def _build_dist_config(name: str, defaults: dict, overrides: dict | None) -> dict:
    """Merge defaults+overrides for one dist and normalise/validate its values."""
    cfg = {**defaults, **(overrides or {})}
    cfg["name"] = name

    # List fields may be given as a bare string; wrap them.
    for key in ("components", "architectures"):
        if isinstance(cfg[key], str):
            cfg[key] = [cfg[key]]

    # allowed_signers: always a list of strings.
    signers = cfg.get("allowed_signers") or []
    if isinstance(signers, str):
        signers = [signers]
    cfg["allowed_signers"] = [str(s) for s in signers]

    # sign_with is passed verbatim to gpg as a key id, so it MUST be a string.
    # YAML silently parses unquoted values like 0xDEADBEEF (hex) or all-digit
    # key ids as integers, and str() of those would not round trip to the
    # intended key id -- so refuse rather than guess.
    sign_with = cfg.get("sign_with")
    if sign_with is not None and not isinstance(sign_with, str):
        die(
            f"Config error: 'sign_with' for dist '{name}' must be a quoted "
            f"string, but YAML parsed it as {type(sign_with).__name__} "
            f"({sign_with!r}). Quote the key id in the config, e.g.:\n"
            f"    sign_with: \"0xDEADBEEFCAFEBABE\""
        )

    # Free-text fields: coerce to str so number-like values (e.g. a suite
    # named '12') don't break path building or Release generation.
    for key in ("suite", "origin", "label", "description"):
        if cfg.get(key) is not None:
            cfg[key] = str(cfg[key])

    return cfg


def load_config(path: Path) -> dict:
    raw = _load_raw_config(path)
    repo = raw["repo"]

    defaults = {**CONFIG_DEFAULTS, **raw.get("defaults", {})}
    dists = {
        name: _build_dist_config(name, defaults, overrides)
        for name, overrides in raw["dists"].items()
    }

    incoming_dir = repo.get("incoming_dir")
    signer_keyring = repo.get("signer_keyring")

    return {
        "base_dir": Path(repo["base_dir"]).expanduser(),
        "incoming_dir": Path(incoming_dir).expanduser() if incoming_dir else None,
        "signer_keyring": Path(signer_keyring).expanduser() if signer_keyring else None,
        "dists": dists,
    }


def _require_dist(cfg: dict, dist_name: str) -> dict:
    """Return the config for *dist_name*, or die if it is not configured."""
    if dist_name not in cfg["dists"]:
        die(f"Unknown dist '{dist_name}'. Known: {', '.join(cfg['dists'])}")
    return cfg["dists"][dist_name]


def _resolve_dists(cfg: dict, requested: list[str] | None) -> list[str]:
    """Validate requested dist names, defaulting to all configured dists.

    *requested* of None (or empty) means "all dists".  Dies on any name that
    is not configured.
    """
    dists = list(requested) if requested else list(cfg["dists"])
    for d in dists:
        if d not in cfg["dists"]:
            die(f"Unknown dist '{d}'. Known: {', '.join(cfg['dists'])}")
    return dists


# ---------------------------------------------------------------------------
# command: init
# ---------------------------------------------------------------------------

def cmd_init(cfg: dict):
    """Create the directory structure for all configured dists."""
    base_dir = cfg["base_dir"]
    base_dir.mkdir(parents=True, exist_ok=True)
    print(f"Initialising repo at {base_dir}")
    for dist_name, dist_cfg in cfg["dists"].items():
        for component in dist_cfg["components"]:
            for arch in dist_cfg["architectures"]:
                d = packages_path(base_dir, dist_name, component, arch)
                d.mkdir(parents=True, exist_ok=True)
                idx = d / "Packages"
                if not idx.exists():
                    idx.write_bytes(b"")
        print(f"  Created structure for dist '{dist_name}'")

        # If suite differs from the dist name, create a symlink so clients
        # using either name can find the dist.
        # e.g. dist 'bookworm' with suite 'stable' -> dists/stable -> bookworm
        suite = dist_cfg.get("suite")
        if suite and suite != dist_name:
            suite_link = dists_path(base_dir, suite)
            if suite_link.is_symlink():
                if suite_link.resolve() == dists_path(base_dir, dist_name).resolve():
                    print(f"  Suite symlink already up to date: dists/{suite} -> {dist_name}")
                else:
                    old_target = os.readlink(suite_link)
                    suite_link.unlink()
                    suite_link.symlink_to(dist_name)
                    print(f"  Updated suite symlink: dists/{suite} -> {dist_name} (was {old_target})")
            elif suite_link.exists():
                warn(
                    f"Cannot create suite symlink dists/{suite} -> {dist_name}: "
                    f"path exists and is not a symlink."
                )
            else:
                suite_link.symlink_to(dist_name)
                print(f"  Created suite symlink: dists/{suite} -> {dist_name}")

    write_repo_metadata(cfg)
    print("Done.")


# ---------------------------------------------------------------------------
# command: add
# ---------------------------------------------------------------------------

def cmd_add(cfg: dict, dist_name: str, deb_paths: list[Path],
            component: str | None = None):
    """Add one or more .deb files to a dist."""
    dist_cfg = _require_dist(cfg, dist_name)
    base_dir = cfg["base_dir"]

    if component is None:
        component = dist_cfg["components"][0]
    elif component not in dist_cfg["components"]:
        die(
            f"Component '{component}' is not configured for dist '{dist_name}'. "
            f"Known components: {', '.join(dist_cfg['components'])}"
        )

    for deb_path in deb_paths:
        if not deb_path.exists():
            warn(f"File not found, skipping: {deb_path}")
            continue

        print(f"\nAdding {deb_path.name} -> {dist_name}/{component}")
        try:
            meta = read_deb(deb_path)
        except ValueError as e:
            die(f"Refusing to add {deb_path.name}: {e}")
        print(f"  Package: {meta['package']}  Version: {meta['version']}  Arch: {meta['arch']}")
        print(f"  Source:  {meta['source']}")

        if meta["arch"] not in dist_cfg["architectures"] and meta["arch"] != "all":
            warn(
                f"Architecture '{meta['arch']}' is not listed for dist '{dist_name}' "
                f"({', '.join(dist_cfg['architectures'])}). Adding anyway."
            )

        add_to_pool(base_dir, dist_name, component, meta, deb_path)

    # Regenerate indices for this dist
    _regenerate(cfg, [dist_name])


# ---------------------------------------------------------------------------
# command: remove
# ---------------------------------------------------------------------------

def cmd_remove(cfg: dict, dist_name: str,
               package: str, version: str, arch: str | None):
    """Remove a package version from the pool and regenerate indices."""
    dist_cfg = _require_dist(cfg, dist_name)
    base_dir = cfg["base_dir"]
    removed = 0

    for component in dist_cfg["components"]:
        for meta in scan_pool(base_dir, dist_name, component):
            if meta["package"] != package:
                continue
            if meta["version"] != version:
                continue
            if arch and meta["arch"] != arch:
                continue
            pool_path = meta["pool_path"]
            print(f"  [remove] {pool_path.relative_to(base_dir)}")
            remove_pool_file(pool_path)
            removed += 1

    if removed == 0:
        warn(f"No matching packages found for {package} {version}" +
             (f" {arch}" if arch else ""))
    else:
        print(f"  Removed {removed} file(s).")
        _regenerate(cfg, [dist_name])


# ---------------------------------------------------------------------------
# command: update
# ---------------------------------------------------------------------------

def cmd_update(cfg: dict, dist_name: str | None):
    """Regenerate indices for one or all dists."""
    dists = _resolve_dists(cfg, [dist_name] if dist_name else None)
    _regenerate(cfg, dists)


# ---------------------------------------------------------------------------
# command: list
# ---------------------------------------------------------------------------

def cmd_list(cfg: dict, dist_name: str | None):
    """List packages in one or all dists."""
    base_dir = cfg["base_dir"]
    dists = [dist_name] if dist_name else list(cfg["dists"])

    for dist_name in dists:
        if dist_name not in cfg["dists"]:
            warn(f"Unknown dist '{dist_name}', skipping.")
            continue
        dist_cfg = cfg["dists"][dist_name]
        print(f"\n{'='*60}")
        print(f"Dist: {dist_name}  ({', '.join(dist_cfg['components'])} | "
              f"{', '.join(dist_cfg['architectures'])})")
        print(f"{'='*60}")

        all_entries = []
        for component in dist_cfg["components"]:
            for meta in scan_pool(base_dir, dist_name, component):
                all_entries.append((component, meta))

        if not all_entries:
            print("  (empty)")
            continue

        all_entries.sort(key=lambda x: (x[1]["package"], x[1]["version"], x[1]["arch"]))
        fmt = "  {:<30}  {:<20}  {:<8}  {}"
        print(fmt.format("Package", "Version", "Arch", "Component"))
        print("  " + "-" * 70)
        for component, meta in all_entries:
            print(fmt.format(
                meta["package"], meta["version"], meta["arch"], component
            ))


# ---------------------------------------------------------------------------
# command: ingest
# ---------------------------------------------------------------------------

def _authorise_signer(dist_name: str, dist_cfg: dict,
                      valid_fingerprints: list[str]) -> str:
    """Enforce the per-dist allow-list against already-verified signatures.

    *valid_fingerprints* are the certificate fingerprints that produced a
    cryptographically valid signature.  This function decides whether any of
    them is permitted to upload to *dist_name*.  Returns the matched
    fingerprint, or raises ValueError.
    """
    allowed_signers = dist_cfg.get("allowed_signers", [])
    if not allowed_signers:
        raise ValueError(
            f"No allowed_signers configured for dist '{dist_name}'. "
            f"Add at least one key fingerprint to accept uploads."
        )
    for kid in allowed_signers:
        if len(_normalise_keyid(kid)) == 8:
            warn(
                f"Short key ID '{kid}' in allowed_signers is insecure. "
                f"Use the full 40-char fingerprint."
            )

    matched = next((fp for fp in valid_fingerprints if _fingerprint_matches(fp, allowed_signers)), None)
    if matched is None:
        raise ValueError(
            f"Valid signature(s) from {', '.join(valid_fingerprints)} but none "
            f"are in the allowed_signers list for dist '{dist_name}'. "
            f"Configured: {allowed_signers}"
        )
    return matched


def _validate_changes_components(changes_info: dict, dist_cfg: dict):
    """Raise if any file's component is not configured for the target dist."""
    for entry in changes_info["files"]:
        comp = entry["component"]
        if comp not in dist_cfg["components"]:
            raise ValueError(
                f"Component '{comp}' (from .changes) is not configured for "
                f"dist '{changes_info['distribution']}'. "
                f"Known: {', '.join(dist_cfg['components'])}"
            )


def _add_changes_to_pool(cfg: dict, dist_name: str, dist_cfg: dict,
                         changes_info: dict, verified_paths: list[Path]):
    """Add every verified .deb referenced by the .changes to the pool."""
    base_dir = cfg["base_dir"]
    for entry, deb_path in zip(changes_info["files"], verified_paths):
        meta = read_deb(deb_path)

        if meta["arch"] not in dist_cfg["architectures"] and meta["arch"] != "all":
            warn(
                f"Architecture '{meta['arch']}' is not listed for dist "
                f"'{dist_name}'. Adding anyway."
            )

        add_to_pool(base_dir, dist_name, entry["component"], meta, deb_path)


def _process_one_changes(cfg: dict, changes_path: Path, incoming_dir: Path,
                         certs: list, dists_to_update: set[str]):
    """Process a single .changes file. Raises on any error."""

    # Verify the signature FIRST, against the whole keyring, so that
    # everything parsed afterwards comes from cryptographically verified
    # bytes -- never from the raw file.
    valid_fingerprints, payload = verify_changes_signature(changes_path, certs)

    # Parse the *verified* payload.
    try:
        changes_info = parse_changes(payload)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Could not parse .changes file: {e}") from e

    dist_name = changes_info["distribution"]
    print(f"  Source:  {changes_info['source']}  {changes_info['version']}")
    print(f"  Dist:    {dist_name}")

    # Check the target dist is known.
    if dist_name not in cfg["dists"]:
        raise ValueError(
            f"Distribution '{dist_name}' is not configured in this repo. "
            f"Known dists: {', '.join(cfg['dists'])}"
        )
    dist_cfg = cfg["dists"][dist_name]

    # Authorise: the (valid) signer must be allowed for THIS dist.
    matched = _authorise_signer(dist_name, dist_cfg, valid_fingerprints)
    print(f"  Signed by: {matched}")

    # Check the file list, verify checksums, and validate components.
    if not changes_info["files"]:
        raise ValueError("No .deb files listed in .changes")

    print(f"  Files ({len(changes_info['files'])}):")
    for entry in changes_info["files"]:
        print(f"    {entry['filename']}  [{entry['component']}/{entry['section']}]")

    verified_paths = verify_changes_files(changes_info, incoming_dir)
    _validate_changes_components(changes_info, dist_cfg)

    # Add each .deb to the pool, then move processed files to done/.
    _add_changes_to_pool(cfg, dist_name, dist_cfg, changes_info, verified_paths)
    dists_to_update.add(dist_name)

    _move_to(changes_path, incoming_dir / "done")
    for deb_path in verified_paths:
        _move_to(deb_path, incoming_dir / "done")
    print(f"  [OK] Moved to done/")


def cmd_ingest(cfg: dict, incoming_dir: Path | None):
    """Process all signed .changes files in the incoming directory."""

    if incoming_dir is None:
        incoming_dir = cfg.get("incoming_dir")
    if incoming_dir is None:
        die(
            "No incoming directory specified. Pass it as an argument or set "
            "'incoming_dir' under 'repo:' in the config."
        )
    incoming_dir = Path(incoming_dir)
    if not incoming_dir.exists():
        die(f"Incoming directory does not exist: {incoming_dir}")

    # Signature verification needs the build servers' public certs.
    keyring = cfg.get("signer_keyring")
    if keyring is None:
        die(
            "No signer_keyring configured. Set 'signer_keyring' under 'repo:' "
            "in the config to a file or directory containing the public keys "
            "allowed to sign uploads."
        )
    certs = load_signer_certs(keyring)
    print(f"Loaded {len(certs)} signer certificate(s) from {keyring}")

    changes_files = sorted(incoming_dir.glob("*.changes"))
    if not changes_files:
        print(f"No .changes files found in {incoming_dir}")
        return

    print(f"Processing {len(changes_files)} .changes file(s) from {incoming_dir}")

    done_dir = incoming_dir / "done"
    failed_dir = incoming_dir / "failed"
    done_dir.mkdir(exist_ok=True)
    failed_dir.mkdir(exist_ok=True)

    dists_to_update: set[str] = set()

    for changes_path in changes_files:
        print(f"\n--- {changes_path.name} ---")
        try:
            _process_one_changes(cfg, changes_path, incoming_dir, certs, dists_to_update)
        except Exception as e:
            print(f"  [FAILED] {e}", file=sys.stderr)
            # Move the .changes to failed/.  Referenced .deb files are left in
            # place: a parse/verify failure means we cannot reliably attribute
            # them, and they may be shared with another .changes.
            _move_to(changes_path, failed_dir)
            continue

    # Regenerate all affected dists once, after processing everything
    _regenerate(cfg, dists_to_update)


# ---------------------------------------------------------------------------
# command: prune
# ---------------------------------------------------------------------------

def _group_pool_versions(base_dir: Path, dist_name: str, component: str,
                         packages: list[str] | None
                         ) -> dict[tuple[str, str], list[tuple[str, Path]]]:
    """Group a dist+component's pool into {(package, arch): [(version, path)]}.

    If *packages* is given, only those package names are included.
    """
    groups: dict[tuple[str, str], list[tuple[str, Path]]] = {}
    for meta in scan_pool(base_dir, dist_name, component):
        pkg = meta["package"]
        if packages is not None and pkg not in packages:
            continue
        key = (pkg, meta["arch"])
        groups.setdefault(key, []).append((meta["version"], meta["pool_path"]))
    return groups


def _select_versions_to_remove(versions: list[tuple[str, Path]], keep: int
                               ) -> tuple[list[tuple[str, Path]],
                                          list[tuple[str, Path]]]:
    """Split (version, path) entries into (to_keep, to_remove), newest first.

    Sorting uses apt_pkg.version_compare so Debian version ordering is
    respected (epochs, tildes, revisions): e.g. 2:1.0 > 1.0, 1.0-2 > 1.0-1,
    1.0 > 1.0~rc1.
    """
    sorted_versions = sorted(
        versions,
        key=functools.cmp_to_key(
            lambda a, b: apt_pkg.version_compare(a[0], b[0])
        ),
        reverse=True,
    )
    return sorted_versions[:keep], sorted_versions[keep:]


def cmd_prune(cfg: dict, keep: int, dists: list[str] | None,
              components: list[str] | None, packages: list[str] | None,
              dry_run: bool):
    """Remove old package versions from the pool, keeping the <keep> newest.

    Versions are sorted using apt_pkg.version_compare so Debian version
    ordering is respected (e.g. 1.0-2 > 1.0-1, 2:1.0 > 1.0).

    Pruning scope:
      - dists:      limit to these dist names      (default: all configured)
      - components: limit to these component names (default: all in each dist)
      - packages:   limit to these package names   (default: all packages)

    Within each (dist, component, package, arch) group the newest <keep>
    versions are retained; older ones are deleted.  After pruning the affected
    dists are regenerated (skipped in dry-run mode).
    """
    if keep < 1:
        die("--keep must be at least 1.")

    base_dir = cfg["base_dir"]
    target_dists = _resolve_dists(cfg, dists)

    mode = "[DRY RUN] " if dry_run else ""
    print(f"{mode}Pruning: keep {keep} version(s) per package per arch")
    if dists:
        print(f"  Dists:      {', '.join(dists)}")
    if components:
        print(f"  Components: {', '.join(components)}")
    if packages:
        print(f"  Packages:   {', '.join(packages)}")

    total_removed = 0
    dists_to_update: set[str] = set()

    for dist_name in target_dists:
        dist_cfg = cfg["dists"][dist_name]
        target_components = [
            c for c in dist_cfg["components"]
            if components is None or c in components
        ]

        for component in target_components:
            groups = _group_pool_versions(base_dir, dist_name, component, packages)

            for (pkg, arch), versions in sorted(groups.items()):
                if len(versions) <= keep:
                    continue  # nothing to prune here

                to_keep, to_remove = _select_versions_to_remove(versions, keep)

                print(
                    f"  {dist_name}/{component}  {pkg} [{arch}]:\n"
                    f"    keep:   {', '.join(v for v, _ in to_keep)}\n"
                    f"    remove: {', '.join(v for v, _ in to_remove)}"
                )

                if not dry_run:
                    for _ver, pool_path in to_remove:
                        remove_pool_file(pool_path)
                    dists_to_update.add(dist_name)

                total_removed += len(to_remove)

    if total_removed == 0:
        print("  Nothing to prune.")
        return

    if dry_run:
        print(f"\n[DRY RUN] Would remove {total_removed} package file(s). "
              f"Re-run without --dry-run to apply.")
    else:
        print(f"\nRemoved {total_removed} package file(s).")
        _regenerate(cfg, dists_to_update)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Private APT repository manager", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("-c", "--config", default="/etc/whawty/aptrepo.yml", help="Path to config file (default: /etc/whawty/aptrepo.yml)")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # init
    p_ini = sub.add_parser("init", help="Initialise directory structure")

    # add
    p_add = sub.add_parser("add", help="Add .deb file(s) to a dist")
    p_add.add_argument("dist", help="Target distribution name")
    p_add.add_argument("-C", "--component", default=None, help="Component to add to (default: first component configured for the dist)")
    p_add.add_argument("debs", nargs="+", metavar="file.deb", help=".deb file(s) to add")

    # remove
    p_rem = sub.add_parser("remove", help="Remove a package version from a dist")
    p_rem.add_argument("dist", help="Distribution name")
    p_rem.add_argument("package", help="Package name")
    p_rem.add_argument("version", help="Package version")
    p_rem.add_argument("arch", nargs="?", default=None, help="Architecture (optional; removes all if omitted)")

    # update
    p_upd = sub.add_parser("update", help="Regenerate indices (all dists or one)")
    p_upd.add_argument("dist", nargs="?", default=None, help="Dist to update (default: all)")

    # list
    p_lst = sub.add_parser("list", help="List packages")
    p_lst.add_argument("dist", nargs="?", default=None, help="Dist to list (default: all)")

    # ingest
    p_ing = sub.add_parser("ingest", help="Ingest signed .changes files from the incoming directory")
    p_ing.add_argument("incoming_dir", nargs="?", default=None, help="Incoming directory (overrides repo.incoming_dir from config)")

    # prune
    p_prn = sub.add_parser("prune", help="Remove old package versions, keeping the N newest per package")
    p_prn.add_argument("keep", type=int, metavar="N", help="Number of versions to keep per package per arch")
    p_prn.add_argument("-d", "--dist", dest="dists", action="append", metavar="DIST", help="Limit to this dist (repeatable; default: all dists)")
    p_prn.add_argument("-C", "--component", dest="components", action="append", metavar="COMPONENT",
                       help="Limit to this component (repeatable; default: all components)")
    p_prn.add_argument("-p", "--package", dest="packages", action="append", metavar="PACKAGE",
                       help="Limit to this package name (repeatable; default: all packages)")
    p_prn.add_argument("-n", "--dry-run", action="store_true", help="Print what would be removed without actually removing anything")

    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.exists():
        die(f"Config file not found: {config_path}")
    cfg = load_config(config_path)
    apt_pkg.init()

    if args.command == "init":
        cmd_init(cfg)
    elif args.command == "add":
        cmd_add(cfg, args.dist, [Path(p) for p in args.debs], args.component)
    elif args.command == "remove":
        cmd_remove(cfg, args.dist, args.package, args.version, args.arch)
    elif args.command == "update":
        cmd_update(cfg, args.dist)
    elif args.command == "list":
        cmd_list(cfg, args.dist)
    elif args.command == "ingest":
        cmd_ingest(cfg, args.incoming_dir)
    elif args.command == "prune":
        cmd_prune(cfg, args.keep, args.dists, args.components, args.packages, args.dry_run)


if __name__ == "__main__":
    main()
