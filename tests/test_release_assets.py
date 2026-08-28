from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import prepare_release

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.0.0"
TAG = f"v{VERSION}"
SOURCE_COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 315532800


class ReleaseAssetTests(unittest.TestCase):
    @staticmethod
    def prepare(parent: Path, name: str) -> tuple[Path, ...]:
        return prepare_release.prepare_release(
            PROJECT_ROOT,
            parent / name,
            VERSION,
            TAG,
            SOURCE_COMMIT,
            SOURCE_DATE_EPOCH,
        )

    def test_repeat_builds_are_byte_identical_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.prepare(root, "first")
            second = self.prepare(root, "second")
            self.assertEqual(prepare_release.expected_asset_names(VERSION), tuple(path.name for path in first))
            self.assertEqual([path.read_bytes() for path in first], [path.read_bytes() for path in second])

            zip_name = f"AWS-GovHawk-Efficiency-Analyzer-v{VERSION}.zip"
            with zipfile.ZipFile(root / "first" / zip_name) as archive:
                members = archive.infolist()
                self.assertEqual([member.filename for member in members], sorted(member.filename for member in members))
                self.assertTrue(all(member.compress_type == zipfile.ZIP_STORED for member in members))
                self.assertTrue(all(member.create_system == 3 for member in members))
                self.assertTrue(all(stat.S_IMODE(member.external_attr >> 16) == 0o644 for member in members))

    def test_assets_bind_source_dependencies_checksums_and_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = self.prepare(root, "release")
            by_name = {path.name: path for path in outputs}
            runtime_name = f"AWS-GovHawk-Efficiency-Analyzer-v{VERSION}.py"
            self.assertEqual(
                (PROJECT_ROOT / "AWS_GovCloud_Analyzer.py").read_bytes(), by_name[runtime_name].read_bytes()
            )

            checksum_lines = by_name["SHA256SUMS.txt"].read_text(encoding="ascii").splitlines()
            self.assertEqual(len(checksum_lines), 3)
            for line in checksum_lines:
                digest, name = line.split("  ", maxsplit=1)
                self.assertEqual(hashlib.sha256(by_name[name].read_bytes()).hexdigest(), digest)

            spdx_name = f"AWS-GovHawk-Efficiency-Analyzer-v{VERSION}.spdx.json"
            spdx = json.loads(by_name[spdx_name].read_text(encoding="utf-8"))
            dependencies = prepare_release.parse_runtime_dependencies(PROJECT_ROOT)
            self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
            self.assertEqual(spdx["packages"][0]["versionInfo"], VERSION)
            self.assertEqual(spdx["packages"][0]["filesAnalyzed"], False)
            self.assertEqual(len(spdx["packages"]), len(dependencies) + 1)
            dependency_purls = {package["externalRefs"][0]["referenceLocator"] for package in spdx["packages"][1:]}
            self.assertEqual(
                dependency_purls,
                {f"pkg:pypi/{dependency['normalized_name']}@{dependency['version']}" for dependency in dependencies},
            )

            evidence = json.loads(by_name["release-evidence.json"].read_text(encoding="utf-8"))
            self.assertEqual(evidence["source_commit"], SOURCE_COMMIT)
            self.assertEqual(evidence["source_date_epoch"], SOURCE_DATE_EPOCH)
            self.assertEqual(evidence["dependencies"], dependencies)
            self.assertEqual(evidence["expected_release_assets"], list(prepare_release.expected_asset_names(VERSION)))
            self.assertEqual(len(evidence["zip_members"]), len(prepare_release.PACKAGE_FILES))
            self.assertEqual(
                evidence["runtime_source_sha256"],
                hashlib.sha256((PROJECT_ROOT / "AWS_GovCloud_Analyzer.py").read_bytes()).hexdigest(),
            )
            for artifact in evidence["artifacts"]:
                path = by_name[artifact["name"]]
                self.assertEqual(artifact["bytes"], path.stat().st_size)
                self.assertEqual(artifact["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

            zip_name = f"AWS-GovHawk-Efficiency-Analyzer-v{VERSION}.zip"
            with zipfile.ZipFile(by_name[zip_name]) as archive:
                for record in evidence["zip_members"]:
                    value = archive.read(record["name"])
                    self.assertEqual(record["bytes"], len(value))
                    self.assertEqual(record["sha256"], hashlib.sha256(value).hexdigest())
                    self.assertEqual(record["type"], "file")

    def test_invalid_identity_and_existing_output_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(prepare_release.ReleaseError):
                prepare_release.prepare_release(
                    PROJECT_ROOT,
                    root / "bad-version",
                    "2.0.1",
                    TAG,
                    SOURCE_COMMIT,
                    SOURCE_DATE_EPOCH,
                )
            with self.assertRaisesRegex(prepare_release.ReleaseError, "range"):
                prepare_release.prepare_release(
                    PROJECT_ROOT,
                    root / "bad-epoch",
                    VERSION,
                    TAG,
                    SOURCE_COMMIT,
                    SOURCE_DATE_EPOCH - 1,
                )
            occupied = root / "occupied"
            occupied.mkdir()
            marker = occupied / "preserve.txt"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(prepare_release.ReleaseError, "already exists"):
                self.prepare(root, "occupied")
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_nonportable_package_paths_fail_closed(self):
        for name in ("../escape", "/absolute", "C:/drive", "CON.txt", "dir\\file"):
            with self.subTest(name=name), self.assertRaises(prepare_release.ReleaseError):
                prepare_release.validate_relative_name(name)


if __name__ == "__main__":
    unittest.main()
