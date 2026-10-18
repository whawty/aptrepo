"""Integration tests for aptrepo.py.

These drive the script end-to-end through its command-line interface under the
interpreter running the tests, so they exercise the real dependencies
(python-apt for reading .debs and building Packages indices, and pysequoia for
verifying signed .changes files).

Run from the repository root:

    python3 -m unittest discover -t . -s tests -v

External tools used: dpkg-deb (to build test packages).  Tests that need a
tool or library that is unavailable are skipped rather than failed.
"""

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APTREPO = REPO_ROOT / "aptrepo.py"

HAVE_DPKG_DEB = shutil.which("dpkg-deb") is not None

try:
    import pysequoia  # noqa: F401
    HAVE_PYSEQUOIA = True
except Exception:
    HAVE_PYSEQUOIA = False


def build_deb(dest_dir: Path, package: str, version: str,
              arch: str = "amd64", description: str | None = None) -> Path:
    """Build a minimal installable .deb with dpkg-deb and return its path.

    *description* can be varied to produce a byte-different package for the
    same package/version/arch triple, which is exactly the case per-dist pools
    (and per-dist incoming directories) exist to support.
    """
    staging = dest_dir / f"{package}-{version}-{arch}-build"
    (staging / "DEBIAN").mkdir(parents=True)
    (staging / "DEBIAN" / "control").write_text(
        f"Package: {package}\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n"
        f"Maintainer: Test <test@example.com>\n"
        f"Description: {description or f'Test package {package} {version}'}\n"
    )
    out = dest_dir / f"{package}_{version}_{arch}.deb"
    subprocess.run(["dpkg-deb", "--build", str(staging), str(out)],
                   check=True, capture_output=True)
    return out


@unittest.skipUnless(HAVE_DPKG_DEB, "dpkg-deb not available")
class AptRepoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="aptrepo-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.base = self.tmp / "repo"
        self.incoming = self.tmp / "incoming"
        self.incoming.mkdir()
        self.pkgdir = self.tmp / "pkgs"
        self.pkgdir.mkdir()
        self.config = self.tmp / "aptrepo.yml"
        self.write_config()

    def write_config(self, signer_keyring: str | None = None,
                     allowed_signers: list[str] | None = None,
                     dists: dict[str, dict] | None = None):
        """Write a test config.

        *dists* maps dist name -> extra per-dist YAML keys (e.g. {"suite": …}).
        """
        if dists is None:
            dists = {"bookworm": {}}
        lines = [
            "repo:",
            f"  base_dir: {self.base}",
            f"  incoming_dir: {self.incoming}",
        ]
        if signer_keyring:
            lines.append(f"  signer_keyring: {signer_keyring}")
        lines += [
            "defaults:",
            "  components: [main]",
            "  architectures: [amd64]",
            "  sign_with: ~",
        ]
        if allowed_signers:
            quoted = ", ".join(f'"{s}"' for s in allowed_signers)
            lines.append(f"  allowed_signers: [{quoted}]")
        lines.append("dists:")
        for name, extra in dists.items():
            lines.append(f"  {name}:")
            lines.append(f"    description: Test dist {name}")
            for key, value in extra.items():
                lines.append(f"    {key}: {value}")
        self.config.write_text("\n".join(lines) + "\n")

    def incoming_for(self, dist: str) -> Path:
        """Create and return the per-dist incoming directory."""
        d = self.incoming / dist
        d.mkdir(parents=True, exist_ok=True)
        return d

    def aptrepo(self, *args, expect_success=True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [sys.executable, str(APTREPO), "-c", str(self.config), *args],
            capture_output=True, text=True,
        )
        if expect_success:
            self.assertEqual(
                result.returncode, 0,
                msg=f"command {args} failed:\n{result.stdout}\n{result.stderr}",
            )
        return result

    # -- tests ---------------------------------------------------------------

    def test_init_creates_structure(self):
        self.aptrepo("init")
        self.assertTrue((self.base / "repo.json").is_file())
        # init scaffolds an empty Packages index; Release is produced later by
        # add/update, so it is not expected immediately after init.
        self.assertTrue(
            (self.base / "dists/bookworm/main/binary-amd64/Packages").is_file()
        )

    def test_empty_component_index_is_empty(self):
        """apt rejects a Packages file that holds only a newline, so an
        empty component's index must stay a zero-byte file after updates."""
        self.write_config(dists={"bookworm": {"components": "[main, extra]"}})
        self.aptrepo("init")
        deb = build_deb(self.pkgdir, "hello", "1.0")
        self.aptrepo("add", "bookworm", str(deb))
        empty = self.base / "dists/bookworm/extra/binary-amd64/Packages"
        self.assertEqual(empty.read_bytes(), b"")
        full = (self.base / "dists/bookworm/main/binary-amd64/Packages").read_bytes()
        self.assertTrue(full.startswith(b"Package: hello\n"))
        self.assertFalse(full.endswith(b"\n\n\n"))

    def test_add_and_list(self):
        self.aptrepo("init")
        deb = build_deb(self.pkgdir, "hello", "1.0")
        self.aptrepo("add", "bookworm", str(deb))

        pool = self.base / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb"
        self.assertTrue(pool.is_file())

        packages = (self.base
                    / "dists/bookworm/main/binary-amd64/Packages").read_text()
        self.assertIn("Package: hello", packages)
        self.assertIn("Version: 1.0", packages)

        listing = self.aptrepo("list", "bookworm").stdout
        self.assertIn("hello", listing)

    def test_multiple_versions_coexist(self):
        self.aptrepo("init")
        for v in ("1.0", "1.1", "2.0"):
            self.aptrepo("add", "bookworm", str(build_deb(self.pkgdir, "tool", v)))
        debs = sorted(p.name for p in
                      (self.base / "pool/bookworm/main/t/tool").glob("*.deb"))
        self.assertEqual(
            debs,
            ["tool_1.0_amd64.deb", "tool_1.1_amd64.deb", "tool_2.0_amd64.deb"],
        )

    def test_remove(self):
        self.aptrepo("init")
        for v in ("1.0", "2.0"):
            self.aptrepo("add", "bookworm", str(build_deb(self.pkgdir, "tool", v)))
        self.aptrepo("remove", "bookworm", "tool", "1.0")
        remaining = sorted(p.name for p in
                           (self.base / "pool/bookworm/main/t/tool").glob("*.deb"))
        self.assertEqual(remaining, ["tool_2.0_amd64.deb"])

    def test_prune_keeps_newest_debian_ordering(self):
        self.aptrepo("init")
        # Includes an epoch and double-digit revision to exercise apt_pkg's
        # Debian version comparison rather than a naive string sort.
        for v in ("1.0-1", "1.0-2", "1.0-9", "1.0-10", "2:0.1"):
            self.aptrepo("add", "bookworm", str(build_deb(self.pkgdir, "tool", v)))
        self.aptrepo("prune", "2")
        remaining = sorted(p.name for p in
                           (self.base / "pool/bookworm/main/t/tool").glob("*.deb"))
        # Newest two by Debian ordering: 2:0.1 (epoch wins) and 1.0-10.
        self.assertEqual(
            remaining,
            ["tool_1.0-10_amd64.deb", "tool_2:0.1_amd64.deb"],
        )

    def _sign_changes(self, deb: Path, cert, dist="bookworm") -> bytes:
        """Build a .changes manifest for *deb* and clearsign it with *cert*."""
        from pysequoia import sign, SignatureMode
        data = deb.read_bytes()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        size = len(data)
        body = (
            f"Format: 1.8\n"
            f"Source: hello\n"
            f"Binary: hello\n"
            f"Architecture: amd64\n"
            f"Version: 1.0\n"
            f"Distribution: {dist}\n"
            f"Maintainer: Test <test@example.com>\n"
            f"Changed-By: Test <test@example.com>\n"
            f"Description:\n hello - test\n"
            f"Changes:\n hello (1.0) {dist}; urgency=medium\n"
            f"Checksums-Sha256:\n {sha256} {size} {deb.name}\n"
            f"Files:\n {md5} {size} admin optional {deb.name}\n"
        ).encode()
        return bytes(sign(cert.secrets.signer(), body, mode=SignatureMode.CLEAR))

    def _sign_changes_files(self, files: list[Path], cert, dist="bookworm",
                            source="hello", version="1.0") -> bytes:
        """Like _sign_changes, but for any list of files (.deb or other)."""
        from pysequoia import sign, SignatureMode
        sha_lines, file_lines = [], []
        for path in files:
            data = path.read_bytes()
            sha_lines.append(f" {hashlib.sha256(data).hexdigest()} {len(data)} {path.name}")
            file_lines.append(f" {hashlib.md5(data).hexdigest()} {len(data)} admin optional {path.name}")
        body = (
            f"Format: 1.8\n"
            f"Source: {source}\n"
            f"Architecture: amd64\n"
            f"Version: {version}\n"
            f"Distribution: {dist}\n"
            f"Maintainer: Test <test@example.com>\n"
            f"Changes:\n {source} ({version}) {dist}; urgency=medium\n"
            f"Checksums-Sha256:\n" + "\n".join(sha_lines) + "\n"
            f"Files:\n" + "\n".join(file_lines) + "\n"
        ).encode()
        return bytes(sign(cert.secrets.signer(), body, mode=SignatureMode.CLEAR))

    def _signed_setup(self, dists=None):
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        cert = Cert.generate("Build Server <build@example.com>")
        (keyring / "build.asc").write_text(str(cert))
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[cert.fingerprint], dists=dists)
        self.aptrepo("init")
        return cert

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_pool_collision_is_atomic_and_does_not_abort(self):
        """A collision fails only its own .changes, adds none of its files,
        and the rest of the run (other uploads, index regeneration) goes on."""
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")

        # First upload: hello 1.0, ingested normally.
        deb = build_deb(inc, "hello", "1.0", description="original")
        original = deb.read_bytes()
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([deb], cert))
        self.aptrepo("ingest")

        # Second run: a different hello 1.0 (collision) together with a new
        # hello-doc in the same .changes, plus an unrelated good upload.
        build_dir = self.tmp / "second"
        build_dir.mkdir()
        bad = build_deb(build_dir, "hello", "1.0", description="rebuilt")
        doc = build_deb(build_dir, "hello-doc", "1.0")
        for p in (bad, doc):
            shutil.copy(p, inc / p.name)
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([bad, doc], cert))
        other = build_deb(inc, "other", "2.0")
        (inc / "other_2.0_amd64.changes").write_bytes(
            self._sign_changes_files([other], cert, source="other", version="2.0"))

        result = self.aptrepo("ingest")
        self.assertIn("Pool collision", result.stderr)

        pool = self.base / "pool/bookworm/main"
        self.assertFalse((pool / "h/hello/hello-doc_1.0_amd64.deb").exists(),
                         "no file of a colliding .changes may be added")
        self.assertEqual((pool / "h/hello/hello_1.0_amd64.deb").read_bytes(),
                         original, "the pooled file must be left untouched")
        self.assertTrue((inc / "failed" / "hello_1.0_amd64.changes").is_file())
        self.assertTrue((pool / "o/other/other_2.0_amd64.deb").is_file(),
                        "later uploads in the same run must still be ingested")
        packages = (self.base / "dists/bookworm/main/binary-amd64/Packages").read_text()
        self.assertIn("Package: other", packages)

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_moves_buildinfo_to_done(self):
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        buildinfo = inc / "hello_1.0_amd64.buildinfo"
        buildinfo.write_text("Format: 1.0\nSource: hello\n")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([deb, buildinfo], cert))

        self.aptrepo("ingest")
        self.assertTrue((inc / "done" / "hello_1.0_amd64.buildinfo").is_file())
        self.assertFalse(buildinfo.exists())
        self.assertFalse(
            (self.base / "pool/bookworm/main/h/hello/hello_1.0_amd64.buildinfo").exists(),
            "non-.deb files must never be added to the pool")

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_leaves_tampered_buildinfo_in_incoming(self):
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        buildinfo = inc / "hello_1.0_amd64.buildinfo"
        buildinfo.write_text("Format: 1.0\nSource: hello\n")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([deb, buildinfo], cert))
        buildinfo.write_text("Format: 1.0\nSource: evil\n")

        result = self.aptrepo("ingest")
        self.assertIn("mismatch", result.stderr)
        self.assertTrue(buildinfo.exists())
        self.assertTrue((self.base / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").is_file())

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_accepts_authorised_signer(self):
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        cert = Cert.generate("Build Server <build@example.com>")
        (keyring / "build.asc").write_text(str(cert))
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[cert.fingerprint])
        self.aptrepo("init")

        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes(deb, cert))

        self.aptrepo("ingest")
        self.assertTrue(
            (self.base
             / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").is_file()
        )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_rejects_unauthorised_signer(self):
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        authorised = Cert.generate("Authorised <ok@example.com>")
        (keyring / "ok.asc").write_text(str(authorised))
        # Repo trusts only the authorised signer...
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[authorised.fingerprint])
        self.aptrepo("init")

        # ...but the .changes is signed by a different, untrusted key.
        attacker = Cert.generate("Attacker <evil@example.com>")
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes(deb, attacker))

        self.aptrepo("ingest")  # should not crash, but must not accept the file
        self.assertFalse(
            (self.base
             / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").exists(),
            "package from an unauthorised signer must not be ingested",
        )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_same_package_into_two_dists(self):
        """The regression this layout exists for.

        Two build servers upload a same-named package+version+arch for
        different dists.  With a shared incoming directory the uploads would
        collide; with per-dist directories both must survive and land in their
        own pool, keeping their distinct contents.
        """
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        cert = Cert.generate("Build Server <build@example.com>")
        (keyring / "build.asc").write_text(str(cert))
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[cert.fingerprint],
                          dists={"bookworm": {}, "noble": {}})
        self.aptrepo("init")

        uploaded = {}
        for dist in ("bookworm", "noble"):
            inc = self.incoming_for(dist)
            deb = build_deb(inc, "hello", "1.0",
                            description=f"built for {dist}")
            uploaded[dist] = deb.read_bytes()
            (inc / "hello_1.0_amd64.changes").write_bytes(
                self._sign_changes(deb, cert, dist=dist))

        # Sanity: the two uploads really are different files.
        self.assertNotEqual(uploaded["bookworm"], uploaded["noble"])

        self.aptrepo("ingest")

        for dist in ("bookworm", "noble"):
            pooled = (self.base
                      / f"pool/{dist}/main/h/hello/hello_1.0_amd64.deb")
            self.assertTrue(pooled.is_file(),
                            f"missing pooled package for {dist}")
            self.assertEqual(pooled.read_bytes(), uploaded[dist],
                             f"{dist} pool holds the wrong file")

        # done/ is per-dist too, so the archived uploads cannot collide either.
        for dist in ("bookworm", "noble"):
            self.assertTrue(
                (self.incoming / dist / "done" / "hello_1.0_amd64.deb").is_file()
            )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_rejects_wrong_incoming_directory(self):
        """A .changes must declare the dist whose directory it was found in."""
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        cert = Cert.generate("Build Server <build@example.com>")
        (keyring / "build.asc").write_text(str(cert))
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[cert.fingerprint],
                          dists={"bookworm": {}, "noble": {}})
        self.aptrepo("init")

        # Signed for noble, but uploaded into bookworm's incoming directory.
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes(deb, cert, dist="noble"))

        self.aptrepo("ingest")

        for dist in ("bookworm", "noble"):
            self.assertFalse(
                (self.base
                 / f"pool/{dist}/main/h/hello/hello_1.0_amd64.deb").exists(),
                f"misdirected upload must not be ingested into {dist}",
            )
        self.assertTrue(
            (inc / "failed" / "hello_1.0_amd64.changes").is_file(),
            "misdirected .changes should be moved to failed/",
        )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_accepts_suite_alias(self):
        """Distribution: may name the dist's suite instead of the dist."""
        from pysequoia import Cert
        keyring = self.tmp / "signers"
        keyring.mkdir()
        cert = Cert.generate("Build Server <build@example.com>")
        (keyring / "build.asc").write_text(str(cert))
        self.write_config(signer_keyring=str(keyring),
                          allowed_signers=[cert.fingerprint],
                          dists={"bookworm": {"suite": "stable"}})
        self.aptrepo("init")

        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes(deb, cert, dist="stable"))

        self.aptrepo("ingest")
        self.assertTrue(
            (self.base
             / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").is_file()
        )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_rejects_tampered_signed_body(self):
        """Editing the signed text after signing must invalidate the upload.

        Everything downstream acts on the verified payload, so this is the
        check the whole ingest rests on: a .changes whose body no longer
        matches its signature must never be parsed, let alone pooled.
        """
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        signed = self._sign_changes_files([deb], cert)

        tampered = signed.replace(b"Maintainer: Test", b"Maintainer: Evil")
        self.assertNotEqual(tampered, signed, "the fixture must really change the body")
        (inc / "hello_1.0_amd64.changes").write_bytes(tampered)

        self.aptrepo("ingest")
        self.assertFalse(
            (self.base / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").exists(),
            "a .changes with a broken signature must not be ingested",
        )
        self.assertTrue((inc / "failed" / "hello_1.0_amd64.changes").is_file())

    # -- ingest reporting and --dry-run ------------------------------------

    @staticmethod
    def _tree_state(root: Path) -> list[tuple[str, str]]:
        """Every file below *root* with its hash, to detect any change."""
        return sorted(
            (str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob("*") if p.is_file()
        )

    @staticmethod
    def _verdicts(result: subprocess.CompletedProcess) -> dict[str, str]:
        """Map each reported .changes to its status from the ingest report.

        Rejections are printed to stderr and accepted uploads to stdout, so
        both streams are read.
        """
        verdicts = {}
        for line in (result.stdout + result.stderr).splitlines():
            m = re.match(r"\s{2}(ok|FAILED)\s+(\S+\.changes)\b", line)
            if m:
                verdicts[m.group(2)] = m.group(1)
        return verdicts

    def _mixed_queue(self, cert) -> Path:
        """Queue one upload of each outcome: accepted, wrong dist, unsigned."""
        inc = self.incoming_for("bookworm")

        good = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([good], cert))

        # Correctly signed, but declares a dist other than this directory's.
        misdir = build_deb(inc, "misdir", "1.0")
        (inc / "misdir_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([misdir], cert, dist="noble",
                                     source="misdir"))

        # Not an OpenPGP message at all: signature verification must reject it.
        (inc / "junk_1.0_amd64.changes").write_bytes(b"not a signature\n")
        return inc

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_dry_run_changes_nothing(self):
        """--dry-run must not copy, move or regenerate anything."""
        cert = self._signed_setup(dists={"bookworm": {}, "noble": {}})
        inc = self._mixed_queue(cert)

        before = self._tree_state(self.tmp)
        result = self.aptrepo("ingest", "--dry-run")

        self.assertEqual(self._tree_state(self.tmp), before,
                         "a dry run must leave every file untouched")
        self.assertFalse((inc / "done").exists(), "done/ must not be created")
        self.assertFalse((inc / "failed").exists(), "failed/ must not be created")
        self.assertEqual(list((self.base / "pool").rglob("*.deb")), [],
                         "nothing may be added to the pool")
        self.assertIn("[DRY RUN]", result.stdout)
        self.assertIn("Re-run without --dry-run to apply.", result.stdout)

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_dry_run_matches_real_verdicts(self):
        """The dry run must reach exactly the verdicts a real ingest reaches.

        Both modes share _inspect_changes(), and this is what keeps them from
        drifting apart: a dry run that accepted an upload the real ingest
        rejects (or the reverse) would make it useless as a preview.
        """
        cert = self._signed_setup(dists={"bookworm": {}, "noble": {}})
        self._mixed_queue(cert)

        dry = self.aptrepo("ingest", "--dry-run")
        real = self.aptrepo("ingest")

        dry_verdicts = self._verdicts(dry)
        self.assertEqual(dry_verdicts, self._verdicts(real))
        # Guard the fixture itself: a scenario with only one outcome would
        # make the comparison above vacuous.
        self.assertEqual(
            {"hello_1.0_amd64.changes": "ok",
             "misdir_1.0_amd64.changes": "FAILED",
             "junk_1.0_amd64.changes": "FAILED"},
            dry_verdicts,
        )

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_dry_run_reports_unclaimed_files(self):
        """A .deb that no accepted .changes claims must be reported.

        The .deb files of a failed upload are deliberately left in the queue,
        so they accumulate; the dry run is what surfaces them.  This has to
        work even when no .changes file is left to process at all.
        """
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")
        build_deb(inc, "orphan", "9.9")          # no .changes for it

        result = self.aptrepo("ingest", "--dry-run")
        self.assertIn("not claimed by an accepted .changes", result.stdout)
        self.assertIn("unclaimed file(s) left", result.stdout)
        self.assertNotIn("No .changes files found", result.stdout)

        verbose = self.aptrepo("ingest", "--dry-run", "--verbose")
        self.assertIn("orphan_9.9_amd64.deb", verbose.stdout)

        # A real ingest reports the queue it processed, not the leftovers.
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([deb], cert))
        real = self.aptrepo("ingest")
        self.assertNotIn("not claimed by an accepted .changes", real.stdout)

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_reports_one_line_per_changes(self):
        """The report stays compact: one status row per .changes file."""
        cert = self._signed_setup(dists={"bookworm": {}, "noble": {}})
        self._mixed_queue(cert)

        result = self.aptrepo("ingest")
        rows = [ln for ln in (result.stdout + result.stderr).splitlines()
                if re.match(r"\s{2}(ok|FAILED)\s", ln)]
        self.assertEqual(len(rows), 3, f"expected one row per .changes: {rows}")
        # Without --verbose the per-file breakdown must stay out of the report.
        # (The header mentions the signer keyring, so match the detail line's
        # shape rather than the bare word.)
        self.assertNotIn("+ hello_1.0_amd64.deb", result.stdout)
        self.assertNotRegex(result.stdout, r"signer [0-9A-F]{40}\b")

    @unittest.skipUnless(HAVE_PYSEQUOIA, "pysequoia not available")
    def test_ingest_verbose_adds_per_file_detail(self):
        """--verbose names the signer and each file of an upload."""
        cert = self._signed_setup()
        inc = self.incoming_for("bookworm")
        deb = build_deb(inc, "hello", "1.0")
        (inc / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes_files([deb], cert))

        result = self.aptrepo("ingest", "--dry-run", "--verbose")
        self.assertRegex(result.stdout, r"signer [0-9A-F]{40}\b")
        self.assertIn("+ hello_1.0_amd64.deb", result.stdout)
        self.assertIn("[main/admin, amd64]", result.stdout)


if __name__ == "__main__":
    unittest.main()
