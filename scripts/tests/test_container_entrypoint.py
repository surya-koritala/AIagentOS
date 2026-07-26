import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "docker" / "entrypoint.sh"


class ContainerEntrypointTests(unittest.TestCase):
    def run_entrypoint(self, root: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "HOME": str(root),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            **overrides,
        }
        return subprocess.run(
            [
                "sh",
                str(ENTRYPOINT),
                "sh",
                "-c",
                'cat "$XDG_CONFIG_HOME/ai-agent-os/config.toml"',
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_renders_valid_scheduled_backup_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            backup_root = Path(directory) / "backups"
            result = self.run_entrypoint(
                Path(directory),
                AGENTOS_BACKUP_ENABLED="true",
                AGENTOS_BACKUP_ROOT=str(backup_root),
                AGENTOS_BACKUP_INTERVAL_SECONDS="300",
                AGENTOS_BACKUP_RUN_ON_START="false",
                AGENTOS_BACKUP_KEEP_LATEST="5",
                AGENTOS_BACKUP_MAX_AGE_SECONDS="86400",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = tomllib.loads(result.stdout)
        self.assertEqual(
            config["backup"],
            {
                "enabled": True,
                "root": str(backup_root),
                "interval_seconds": 300,
                "run_on_start": False,
                "keep_latest": 5,
                "max_age_seconds": 86400,
            },
        )

    def test_renders_paired_backup_signing_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signing_key = root / "backup-signing.pk8"
            signing_key.write_bytes(b"test-key-material")
            signing_key.chmod(0o600)
            result = self.run_entrypoint(
                root,
                AGENTOS_BACKUP_SIGNING_KEY_PATH=str(signing_key),
                AGENTOS_BACKUP_SIGNING_KEY_ID="release-2026.1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            config = tomllib.loads(result.stdout)
            self.assertEqual(
                config["backup"]["signing_key_path"], str(signing_key)
            )
            self.assertEqual(
                config["backup"]["signing_key_id"], "release-2026.1"
            )

    def test_rejects_relative_or_injectable_root_and_non_numeric_policy(self):
        invalid = (
            {"AGENTOS_BACKUP_ROOT": "relative/backups"},
            {"AGENTOS_BACKUP_ROOT": '/backups"\nenabled = false'},
            {"AGENTOS_BACKUP_INTERVAL_SECONDS": "1h"},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                result = self.run_entrypoint(Path(directory), **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error:", result.stderr)

    def test_rejects_unpaired_or_unsafe_backup_signing_identity(self):
        invalid = (
            {"AGENTOS_BACKUP_SIGNING_KEY_ID": "release-1"},
            {
                "AGENTOS_BACKUP_SIGNING_KEY_PATH": "relative/key.pk8",
                "AGENTOS_BACKUP_SIGNING_KEY_ID": "release-1",
            },
            {
                "AGENTOS_BACKUP_SIGNING_KEY_PATH": "/missing/key.pk8",
                "AGENTOS_BACKUP_SIGNING_KEY_ID": "release-1",
            },
            {
                "AGENTOS_BACKUP_SIGNING_KEY_PATH": "/tmp/key.pk8",
                "AGENTOS_BACKUP_SIGNING_KEY_ID": 'bad"\nenabled=false',
            },
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                result = self.run_entrypoint(Path(directory), **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
