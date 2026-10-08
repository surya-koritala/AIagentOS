import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def job(source, name):
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", source)
    if match is None:
        raise AssertionError(f"missing job {name}")
    return match.group(1)


def condition(body):
    match = re.search(r"(?m)^    if: >-\n((?:      .*\n)+)", body)
    if match:
        return " ".join(line.strip() for line in match.group(1).splitlines())
    match = re.search(r"(?m)^    if: (.*)$", body)
    return match.group(1).strip() if match else None


class ReleaseAssetWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.release = (ROOT / ".github/workflows/release.yml").read_text()
        self.scenario = (ROOT / ".github/workflows/release-assets-scenario.yml").read_text()

    def test_assembly_requires_every_mandatory_success_even_when_optional_jobs_fail(self):
        actual = condition(job(self.release, "assemble"))
        self.assertEqual(actual, condition(job(self.scenario, "assemble")))
        self.assertEqual(actual, (
            "always() && needs.required-ci.result == 'success' && "
            "needs.wedge.result == 'success' && needs.release-artifacts.result == 'success' && "
            "needs.container.result == 'success'"
        ))
        self.assertNotIn("desktop", actual)

    def test_publication_overrides_failed_optional_ancestors_but_requires_successful_assembly(self):
        actual = condition(job(self.release, "publish"))
        self.assertEqual(actual, (
            "always() && startsWith(github.ref, 'refs/tags/v') && needs.assemble.result == 'success'"
        ))
        self.assertEqual(condition(job(self.scenario, "publish-probe")), (
            "always() && needs.assemble.result == 'success'"
        ))
        self.assertIn("needs: assemble", job(self.release, "publish"))

    def test_desktop_defaults_off_and_does_not_remove_signing_contract(self):
        self.assertIn("desktop_assets:\n", self.release)
        self.assertIn("type: boolean\n        default: false", self.release)
        for name in ("desktop-release-contract", "desktop-artifacts"):
            self.assertEqual(condition(job(self.release, name)), (
                "(github.event_name == 'workflow_dispatch' && inputs.desktop_assets) || "
                "(github.event_name == 'push' && vars.DESKTOP_ASSETS_QUALIFIED == 'true')"
            ))
        contract = job(self.release, "desktop-release-contract")
        self.assertIn("Block public tags until native signing and clean-host qualification land", contract)
        self.assertIn("exit 1", contract)
        self.assertIn("python3 scripts/verify_desktop_release.py", contract)

    def test_inventory_precedes_manifest_and_all_assets_receive_supply_chain_proof(self):
        assembly = job(self.release, "assemble")
        self.assertLess(assembly.index("scripts/prepare_release_bundle.py"), assembly.index("scripts/build_desktop_update_manifest.py"))
        self.assertIn("steps.inventory.outputs.updater_ready == 'true'", assembly)
        self.assertLess(assembly.index("cp DISTRIBUTION_NOTES.md"), assembly.index("Generate SHA-256 manifest"))
        for expected in ("pattern: release-*", "merge-multiple: true", "cosign sign-blob", "attest-build-provenance@"):
            self.assertIn(expected, assembly)
        self.assertIn("cat dist/DISTRIBUTION_NOTES.md >> RELEASE_NOTES.md", job(self.release, "publish"))

    def test_dependency_probes_cannot_publish_or_sign_release_assets(self):
        self.assertNotIn("contents: write", self.scenario)
        self.assertNotIn("id-token: write", self.scenario)
        self.assertNotIn("gh release", self.scenario)
        self.assertNotIn("continue-on-error", self.scenario)
        for name in ("required-ci-failed", "wedge-failed", "release-artifacts-failed", "container-failed", "desktop-failed"):
            self.assertIn(name, self.scenario)
        self.assertIn("real_publication_exercised': False", self.scenario)


if __name__ == "__main__":
    unittest.main()
