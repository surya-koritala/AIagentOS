import json
import shutil
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_cli_archive import BINARIES, build_archive
from linux_cli_rc_qualification import (
    QualificationError,
    load_release_fixture,
    sha256_file,
    validate_archive,
    validate_identity,
    validate_report,
    verify_supply_chain,
)


ROOT = Path(__file__).resolve().parents[2]
RELEASE_CANDIDATE = "v0.4.0-rc.1"
COMMIT = "a" * 40


class LinuxCliRcQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for index, name in enumerate(BINARIES):
            path = self.source / name
            path.write_bytes(f"fake-{name}-{index}".encode())
            path.chmod(0o755)
        self.archive = (
            self.root / "agentos-v0.4.0-rc.1-x86_64-unknown-linux-gnu.zip"
        )
        build_archive(self.source, self.archive)

    def tearDown(self):
        self.temporary.cleanup()

    def report(self):
        return {
            "schema_version": 1,
            "qualification_class": "restricted_linux_cli_release_candidate",
            "release_candidate": RELEASE_CANDIDATE,
            "source": {"commit": COMMIT, "dirty": False},
            "artifact": {
                "name": self.archive.name,
                "sha256": sha256_file(self.archive),
                "byte_count": self.archive.stat().st_size,
                "binaries": list(BINARIES),
            },
            "platform": {
                "architecture": "x86_64",
                "os": "ubuntu",
                "version": "22.04",
            },
            "supply_chain": {
                "github_provenance_verified": True,
                "keyless_sigstore_verified": True,
            },
            "upgrade": {
                "released_schema_fixture_verified": True,
                "released_schema_encrypted": True,
                "released_agent_survived": True,
                "released_schema_tag": "v0.3.0",
                "released_schema_source_commit": "534e37e3c962c1fea5ef5e21971ab876e9b283bc",
                "released_schema_sha256": "bd11209f66f8cb89dd1f1015514740426290a76e3beabe223f810cf86720d5a6",
            },
            "runtime": {
                "exact_version_served": True,
                "tls_verified": True,
                "authentication_required": True,
                "wrong_authentication_rejected": True,
                "governed_agent_created": True,
                "gate_counters_observable": True,
                "clean_restart_persisted_state": True,
            },
            "durability": {
                "storage_encrypted": True,
                "backup_signed": True,
                "backup_encrypted": True,
                "recovery_anchor_verified": True,
                "tampered_backup_rejected": True,
                "missing_key_failed_closed": True,
                "fresh_host_restore_completed": True,
                "enforcement_rearmed": True,
                "fresh_host_runtime_verified": True,
                "persisted_agent_count": 2,
            },
            "completed_at": "2026-07-30T00:00:00Z",
            "production_claim_allowed": False,
            "limitations": ["single node", "no live LLM", "no desktop"],
        }

    def write_report(self, value=None):
        path = self.root / "report.json"
        path.write_text(
            json.dumps(self.report() if value is None else value),
            encoding="utf-8",
        )
        return path

    def test_exact_identity_archive_and_released_fixture_are_accepted(self):
        self.assertEqual(validate_identity(RELEASE_CANDIDATE, COMMIT), "0.4.0-rc.1")
        self.assertEqual(set(validate_archive(self.archive)), set(BINARIES))
        fixture, release = load_release_fixture(
            ROOT / "tests/fixtures/storage/releases.toml", "v0.3.0"
        )
        self.assertEqual(fixture.name, "v0.3.0.sql")
        self.assertEqual(release["source_commit"], "534e37e3c962c1fea5ef5e21971ab876e9b283bc")

    def test_non_rc_tag_and_inexact_commit_are_rejected(self):
        for tag in ("v0.4.0", "0.4.0-rc.1", "v0.4.0-rc.0", "v0.4.0-rc.1-extra"):
            with self.subTest(tag=tag), self.assertRaises(QualificationError):
                validate_identity(tag, COMMIT)
        with self.assertRaisesRegex(QualificationError, "40 lowercase"):
            validate_identity(RELEASE_CANDIDATE, "A" * 40)

    def test_extra_duplicate_symlink_and_noncanonical_entries_are_rejected(self):
        extra = self.root / "extra.zip"
        with zipfile.ZipFile(extra, "w") as archive:
            for name in BINARIES:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, b"x")
            archive.writestr("../escape", b"x")
        with self.assertRaisesRegex(QualificationError, "entries differ"):
            validate_archive(extra)

        duplicate = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                for name in BINARIES:
                    for _ in range(2 if name == "agent" else 1):
                        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o755) << 16
                        archive.writestr(info, b"x")
        with self.assertRaisesRegex(QualificationError, "duplicate"):
            validate_archive(duplicate)

        symlink = self.root / "symlink.zip"
        with zipfile.ZipFile(symlink, "w") as archive:
            for name in BINARIES:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                mode = stat.S_IFLNK | 0o755 if name == "agent" else stat.S_IFREG | 0o755
                info.external_attr = mode << 16
                archive.writestr(info, b"x")
        with self.assertRaisesRegex(QualificationError, "not a Unix regular file"):
            validate_archive(symlink)

        timestamp = self.root / "timestamp.zip"
        with zipfile.ZipFile(timestamp, "w") as archive:
            for name in BINARIES:
                date = (2026, 1, 1, 0, 0, 0) if name == "agent" else (1980, 1, 1, 0, 0, 0)
                info = zipfile.ZipInfo(name, date)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, b"x")
        with self.assertRaisesRegex(QualificationError, "non-canonical timestamp"):
            validate_archive(timestamp)

    def test_registry_digest_drift_is_rejected(self):
        fixture_root = self.root / "fixtures"
        fixture_root.mkdir()
        shutil.copy2(ROOT / "tests/fixtures/storage/releases.toml", fixture_root)
        for path in (ROOT / "tests/fixtures/storage").glob("v*.sql"):
            shutil.copy2(path, fixture_root)
        with (fixture_root / "v0.3.0.sql").open("ab") as handle:
            handle.write(b"\n-- tampered\n")
        with self.assertRaisesRegex(QualificationError, "digest does not match"):
            load_release_fixture(fixture_root / "releases.toml", "v0.3.0")

    def test_complete_report_is_exact_and_failed_or_mixed_evidence_is_rejected(self):
        path = self.write_report()
        report = validate_report(
            path,
            release_candidate=RELEASE_CANDIDATE,
            commit=COMMIT,
            archive=self.archive,
            release_registry=ROOT / "tests/fixtures/storage/releases.toml",
            released_schema_tag="v0.3.0",
        )
        self.assertFalse(report["production_claim_allowed"])

        failed = self.report()
        failed["runtime"]["tls_verified"] = False
        path.unlink()
        path = self.write_report(failed)
        with self.assertRaisesRegex(QualificationError, "failed proof"):
            validate_report(
                path,
                release_candidate=RELEASE_CANDIDATE,
                commit=COMMIT,
                archive=self.archive,
                release_registry=ROOT / "tests/fixtures/storage/releases.toml",
                released_schema_tag="v0.3.0",
            )

        mixed = self.report()
        mixed["source"]["commit"] = "b" * 40
        path.unlink()
        path = self.write_report(mixed)
        with self.assertRaisesRegex(QualificationError, "source identity"):
            validate_report(
                path,
                release_candidate=RELEASE_CANDIDATE,
                commit=COMMIT,
                archive=self.archive,
                release_registry=ROOT / "tests/fixtures/storage/releases.toml",
                released_schema_tag="v0.3.0",
            )

    @mock.patch("linux_cli_rc_qualification.time.sleep")
    @mock.patch("linux_cli_rc_qualification.run_command")
    def test_supply_chain_verification_pins_tag_workflow_commit_and_hosted_runner(
        self, run_command_mock, _sleep_mock
    ):
        bundle = self.root / "candidate.zip.sigstore.json"
        bundle.write_text("{}", encoding="utf-8")
        verify_supply_chain(
            self.archive,
            bundle,
            "surya-koritala/AIagentOS",
            RELEASE_CANDIDATE,
            COMMIT,
        )
        commands = [call.args[0] for call in run_command_mock.call_args_list]
        self.assertEqual(commands[0][0], "cosign")
        self.assertIn(
            "https://github.com/surya-koritala/AIagentOS/.github/workflows/"
            "linux-cli-rc.yml@refs/tags/v0.4.0-rc.1",
            commands[0],
        )
        self.assertEqual(commands[1][0:3], ["gh", "attestation", "verify"])
        self.assertIn("--source-digest", commands[1])
        self.assertIn(COMMIT, commands[1])
        self.assertIn("--deny-self-hosted-runners", commands[1])


if __name__ == "__main__":
    unittest.main()
