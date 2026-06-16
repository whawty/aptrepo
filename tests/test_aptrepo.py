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
              arch: str = "amd64") -> Path:
    """Build a minimal installable .deb with dpkg-deb and return its path."""
    staging = dest_dir / f"{package}-{version}-{arch}-build"
    (staging / "DEBIAN").mkdir(parents=True)
    (staging / "DEBIAN" / "control").write_text(
        f"Package: {package}\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n"
        f"Maintainer: Test <test@example.com>\n"
        f"Description: Test package {package} {version}\n"
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
                     allowed_signers: list[str] | None = None):
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
        lines += [
            "dists:",
            "  bookworm:",
            "    description: Test dist",
        ]
        self.config.write_text("\n".join(lines) + "\n")

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

        deb = build_deb(self.incoming, "hello", "1.0")
        (self.incoming / "hello_1.0_amd64.changes").write_bytes(
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
        deb = build_deb(self.incoming, "hello", "1.0")
        (self.incoming / "hello_1.0_amd64.changes").write_bytes(
            self._sign_changes(deb, attacker))

        self.aptrepo("ingest")  # should not crash, but must not accept the file
        self.assertFalse(
            (self.base
             / "pool/bookworm/main/h/hello/hello_1.0_amd64.deb").exists(),
            "package from an unauthorised signer must not be ingested",
        )


if __name__ == "__main__":
    unittest.main()
