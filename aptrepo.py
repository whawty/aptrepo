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

Usage:
  aptrepo.py add    <dist> <file.deb> [file.deb ...]
  aptrepo.py remove <dist> <package> <version> [<arch>]
  aptrepo.py update [<dist>]
  aptrepo.py list   [<dist>]
  aptrepo.py init
"""

import argparse
import gzip
import hashlib
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import apt_inst
import apt_pkg
import yaml

apt_pkg.init()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REWRITE_ORDER = apt_pkg.REWRITE_PACKAGE_ORDER

# Fields to strip from the .deb control before writing to the Packages index.
# We'll add them back ourselves (Filename, Size, hashes).
_STRIP_FIELDS = {"Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512"}

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

CONFIG_DEFAULTS = {
    "components": ["main"],
    "architectures": ["amd64"],
    "sign_with": None,          # GPG key-id, or None to skip signing
    "suite": None,              # falls back to dist name if None
    "label": None,
    "origin": None,
    "description": None,
    "valid_until": None,        # e.g. "30d", "1w" -- not implemented yet, placeholder
}


def load_config(path: Path) -> dict:
    with open(path) as f:
        raw = yaml.safe_load(f)

    if "repo" not in raw:
        die("Config must have a top-level 'repo' section.")
    if "dists" not in raw:
        die("Config must have a top-level 'dists' section.")

    repo = raw["repo"]
    if "base_dir" not in repo:
        die("Config 'repo.base_dir' is required.")

    defaults = {**CONFIG_DEFAULTS, **raw.get("defaults", {})}

    dists = {}
    for name, overrides in raw["dists"].items():
        cfg = {**defaults, **(overrides or {})}
        cfg["name"] = name
        # normalise lists
        for key in ("components", "architectures"):
            if isinstance(cfg[key], str):
                cfg[key] = [cfg[key]]
        dists[name] = cfg

    return {
        "base_dir": Path(repo["base_dir"]).expanduser(),
        "dists": dists,
    }


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def pool_prefix(source_name: str) -> str:
    """Return the first-level pool prefix for a source package name.

    Mirrors Debian upstream behaviour:
      lib* packages  -> first 4 characters  (libc, libp, liba, lib3, …)
      everything else -> first character
    """
    if source_name.startswith("lib") and len(source_name) >= 4:
        return source_name[:4]
    return source_name[0]


def pool_path(base_dir: Path, dist: str, component: str,
              source_name: str, filename: str) -> Path:
    """Absolute path for a .deb inside the pool."""
    prefix = pool_prefix(source_name)
    return base_dir / "pool" / dist / component / prefix / source_name / filename


def dists_path(base_dir: Path, dist: str) -> Path:
    return base_dir / "dists" / dist


def packages_path(base_dir: Path, dist: str, component: str, arch: str) -> Path:
    return dists_path(base_dir, dist) / component / f"binary-{arch}"


# ---------------------------------------------------------------------------
# .deb metadata extraction
# ---------------------------------------------------------------------------

def read_deb(deb_path: Path) -> dict:
    """Extract control fields + file hashes from a .deb.  Returns a dict."""
    deb = apt_inst.DebFile(str(deb_path))
    ctrl_bytes = deb.control.extractdata("control")
    ctrl_text = ctrl_bytes.decode("utf-8", errors="replace")
    section = apt_pkg.TagSection(ctrl_text)

    # Source name (may be "srcname (binversion)", we want just the name)
    raw_src = section.get("Source", section["Package"])
    source_name = raw_src.split()[0]

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

    return {
        "section": section,
        "ctrl_text": ctrl_text,
        "package": section["Package"],
        "version": section["Version"],
        "arch": section["Architecture"],
        "source": source_name,
        "size": size,
        "hashes": hash_map,
    }


# ---------------------------------------------------------------------------
# Packages index building
# ---------------------------------------------------------------------------

def build_packages_entry(meta: dict, filename_rel: str) -> bytes:
    """Produce one stanza for a Packages index file."""
    section = meta["section"]
    ctrl_text = meta["ctrl_text"]

    # Re-parse so we have a fresh TagSection (the original might be shared)
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

    plain = dest_dir / "Packages"
    plain.write_bytes(raw)

    gz = dest_dir / "Packages.gz"
    with gzip.GzipFile(str(gz), "wb", mtime=0) as f:
        f.write(raw)

    xz = dest_dir / "Packages.xz"
    with lzma.open(xz, "wb", format=lzma.FORMAT_XZ) as f:
        f.write(raw)


# ---------------------------------------------------------------------------
# Pool management
# ---------------------------------------------------------------------------

def add_to_pool(base_dir: Path, dist: str, component: str,
                meta: dict, src_path: Path) -> Path:
    """Copy .deb into the pool (if not already identical). Returns pool path."""
    dest = pool_path(base_dir, dist, component,
                     meta["source"], src_path.name)
    if dest.exists():
        # Check if it's identical by SHA256
        with open(dest, "rb") as f:
            existing_hashes = apt_pkg.Hashes(f)
        existing_sha256 = next(
            (h.hashvalue for h in existing_hashes.hashes if h.hashtype == "SHA256"),
            None,
        )
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


def remove_from_pool(base_dir: Path, dist: str, component: str,
                     source_name: str, filename: str) -> bool:
    """Remove a specific file from the pool. Returns True if removed."""
    path = pool_path(base_dir, dist, component, source_name, filename)
    if path.exists():
        path.unlink()
        # Clean up empty parent dirs
        for parent in (path.parent, path.parent.parent, path.parent.parent.parent):
            try:
                parent.rmdir()
            except OSError:
                break
        return True
    return False


def scan_pool(base_dir: Path, dist: str, component: str) -> list[dict]:
    """Scan the pool for a given dist+component, return list of metadata dicts."""
    pool_dir = base_dir / "pool" / dist / component
    if not pool_dir.exists():
        return []

    entries = []
    for deb_path in sorted(pool_dir.rglob("*.deb")):
        try:
            meta = read_deb(deb_path)
            meta["pool_path"] = deb_path
            entries.append(meta)
        except Exception as e:
            warn(f"Could not read {deb_path}: {e}")
    return entries


# ---------------------------------------------------------------------------
# Release file generation
# ---------------------------------------------------------------------------

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
    release_path.write_text("\n".join(lines) + "\n")
    print(f"  [release] Written: {release_path.relative_to(base_dir)}")
    return release_path


# ---------------------------------------------------------------------------
# GPG signing
# ---------------------------------------------------------------------------

def sign_release(release_path: Path, key_id: str):
    """Produce Release.gpg (detached) and InRelease (clearsigned)."""
    base = release_path.parent

    # Detached signature: Release.gpg
    gpg_path = base / "Release.gpg"
    cmd_detach = [
        "gpg", "--batch", "--yes",
        "--armor", "--detach-sign",
    ]
    if key_id:
        cmd_detach += ["--local-user", key_id]
    cmd_detach += ["--output", str(gpg_path), str(release_path)]
    _run_gpg(cmd_detach)
    print(f"  [sign] {gpg_path.name}")

    # Clearsigned: InRelease
    inrelease_path = base / "InRelease"
    cmd_clear = [
        "gpg", "--batch", "--yes",
        "--armor", "--clearsign",
    ]
    if key_id:
        cmd_clear += ["--local-user", key_id]
    cmd_clear += ["--output", str(inrelease_path), str(release_path)]
    _run_gpg(cmd_clear)
    print(f"  [sign] {inrelease_path.name}")


def _run_gpg(cmd: list):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        die(
            f"GPG failed (exit {result.returncode}):\n"
            + result.stderr.decode(errors="replace")
        )


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def cmd_add(cfg: dict, dist_name: str, deb_paths: list[Path],
            component: str | None = None):
    """Add one or more .deb files to a dist."""
    if dist_name not in cfg["dists"]:
        die(f"Unknown dist '{dist_name}'. Known: {', '.join(cfg['dists'])}")

    dist_cfg = cfg["dists"][dist_name]
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
        meta = read_deb(deb_path)
        print(f"  Package: {meta['package']}  Version: {meta['version']}  Arch: {meta['arch']}")
        print(f"  Source:  {meta['source']}")

        if meta["arch"] not in dist_cfg["architectures"] and meta["arch"] != "all":
            warn(
                f"Architecture '{meta['arch']}' is not listed for dist '{dist_name}' "
                f"({', '.join(dist_cfg['architectures'])}). Adding anyway."
            )

        add_to_pool(base_dir, dist_name, component, meta, deb_path)

    # Regenerate indices for this dist
    update_dist(cfg, dist_name)


def cmd_remove(cfg: dict, dist_name: str,
               package: str, version: str, arch: str | None):
    """Remove a package version from the pool and regenerate indices."""
    if dist_name not in cfg["dists"]:
        die(f"Unknown dist '{dist_name}'.")

    dist_cfg = cfg["dists"][dist_name]
    base_dir = cfg["base_dir"]
    removed = 0

    for component in dist_cfg["components"]:
        pool_dir = base_dir / "pool" / dist_name / component
        if not pool_dir.exists():
            continue
        for deb_path in sorted(pool_dir.rglob("*.deb")):
            try:
                meta = read_deb(deb_path)
            except Exception:
                continue
            if meta["package"] != package:
                continue
            if meta["version"] != version:
                continue
            if arch and meta["arch"] != arch:
                continue
            print(f"  [remove] {deb_path.relative_to(base_dir)}")
            deb_path.unlink()
            # clean empty dirs
            for parent in (deb_path.parent, deb_path.parent.parent,
                            deb_path.parent.parent.parent):
                try:
                    parent.rmdir()
                except OSError:
                    break
            removed += 1

    if removed == 0:
        warn(f"No matching packages found for {package} {version}" +
             (f" {arch}" if arch else ""))
    else:
        print(f"  Removed {removed} file(s).")
        update_dist(cfg, dist_name)


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


def cmd_update(cfg: dict, dist_name: str | None):
    """Regenerate indices for one or all dists."""
    dists = [dist_name] if dist_name else list(cfg["dists"])
    for d in dists:
        if d not in cfg["dists"]:
            die(f"Unknown dist '{d}'.")
        update_dist(cfg, d)


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
    print("Done. Run 'update' to regenerate Release files.")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def die(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str):
    print(f"WARNING: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Private APT repository manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-c", "--config",
        default="aptrepo.yaml",
        help="Path to config file (default: aptrepo.yaml)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # add
    p_add = sub.add_parser("add", help="Add .deb file(s) to a dist")
    p_add.add_argument("dist", help="Target distribution name")
    p_add.add_argument(
        "-C", "--component",
        default=None,
        help="Component to add to (default: first component configured for the dist)",
    )
    p_add.add_argument("debs", nargs="+", metavar="file.deb", help=".deb file(s) to add")

    # remove
    p_rem = sub.add_parser("remove", help="Remove a package version from a dist")
    p_rem.add_argument("dist", help="Distribution name")
    p_rem.add_argument("package", help="Package name")
    p_rem.add_argument("version", help="Package version")
    p_rem.add_argument("arch", nargs="?", default=None,
                       help="Architecture (optional; removes all if omitted)")

    # update
    p_upd = sub.add_parser("update", help="Regenerate indices (all dists or one)")
    p_upd.add_argument("dist", nargs="?", default=None,
                       help="Dist to update (default: all)")

    # list
    p_lst = sub.add_parser("list", help="List packages")
    p_lst.add_argument("dist", nargs="?", default=None,
                       help="Dist to list (default: all)")

    # init
    sub.add_parser("init", help="Initialise directory structure")

    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        die(f"Config file not found: {config_path}")
    cfg = load_config(config_path)

    if args.command == "add":
        cmd_add(cfg, args.dist, [Path(p) for p in args.debs], args.component)
    elif args.command == "remove":
        cmd_remove(cfg, args.dist, args.package, args.version, args.arch)
    elif args.command == "update":
        cmd_update(cfg, args.dist)
    elif args.command == "list":
        cmd_list(cfg, args.dist)
    elif args.command == "init":
        cmd_init(cfg)


if __name__ == "__main__":
    main()
